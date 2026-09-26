"""
ChromaDB implementation of the index registry.

This adapter stores project and file metadata in ChromaDB for
efficient change detection and smart re-indexing.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import chromadb
from chromadb.config import Settings


# These collections are used as a key/value store only (lookups by id or
# metadata filter, never semantic queries). Passing explicit placeholder
# embeddings stops ChromaDB from running its default ONNX embedding model on
# every upsert, which otherwise downloads ~80 MB on first use (fails offline)
# and slows indexing. 384 = dimension of Chroma's default model, so existing
# collections stay compatible.
_PLACEHOLDER_DIM = 384


def _placeholder_embeddings(count: int) -> list:
    return [[0.0] * _PLACEHOLDER_DIM for _ in range(count)]

from ...domain.repositories.index_registry import IndexRegistryRepository
from ...domain.value_objects.project_metadata import (
    FileMetadata,
    FileStatus,
    ProjectMetadata,
)


class ChromaIndexRegistryAdapter(IndexRegistryRepository):
    """
    ChromaDB implementation of the index registry.

    Stores metadata in a single ChromaDB collection with two document types:
    - project_{project_id}: Project-level metadata
    - file_{project_id}_{file_hash}: File-level metadata
    """

    def __init__(
        self,
        persist_directory: str = "./falconeye_data/registry",
        collection_name: str = "index_registry",
    ):
        """
        Initialize the ChromaDB registry adapter.

        Args:
            persist_directory: Directory to store ChromaDB data
            collection_name: Name of the registry collection
        """
        self.persist_directory = Path(persist_directory)
        self.collection_name = collection_name

        # Create persist directory if it doesn't exist
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(anonymized_telemetry=False),
        )

        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "FalconEYE index registry for smart re-indexing"},
        )

    # ===== Project Management =====

    def save_project(self, project: ProjectMetadata) -> None:
        """Save or update project metadata."""
        doc_id = f"project_{project.project_id}"

        # Convert to dict for storage
        metadata = project.to_dict()

        # Store in ChromaDB (upsert = add or update)
        self.collection.upsert(
            ids=[doc_id],
            embeddings=_placeholder_embeddings(1),
            documents=[json.dumps(metadata)],  # Store as JSON string
            metadatas=[{"type": "project", "project_id": project.project_id}],
        )

    def get_project(self, project_id: str) -> Optional[ProjectMetadata]:
        """Get project metadata by ID."""
        doc_id = f"project_{project_id}"

        try:
            results = self.collection.get(ids=[doc_id], include=["documents"])

            if results["documents"]:
                data = json.loads(results["documents"][0])
                return ProjectMetadata.from_dict(data)

            return None

        except Exception:
            return None

    def get_all_projects(self) -> List[ProjectMetadata]:
        """Get metadata for all indexed projects."""
        try:
            # Query for all project documents
            results = self.collection.get(
                where={"type": "project"}, include=["documents"]
            )

            projects = []
            for doc_json in results["documents"]:
                data = json.loads(doc_json)
                projects.append(ProjectMetadata.from_dict(data))

            return projects

        except Exception:
            return []

    def delete_project(self, project_id: str) -> bool:
        """Delete project and all associated file metadata."""
        try:
            # Delete project document
            project_doc_id = f"project_{project_id}"
            self.collection.delete(ids=[project_doc_id])

            # Delete all file documents for this project
            file_results = self.collection.get(
                where={"$and": [{"type": "file"}, {"project_id": project_id}]},
                include=["metadatas"],
            )

            if file_results["ids"]:
                self.collection.delete(ids=file_results["ids"])

            return True

        except Exception:
            return False

    def project_exists(self, project_id: str) -> bool:
        """Check if a project exists in the registry."""
        return self.get_project(project_id) is not None

    # ===== File Management =====

    def save_file(self, file_meta: FileMetadata) -> None:
        """Save or update file metadata."""
        doc_id = self._get_file_doc_id(file_meta.project_id, file_meta.file_path)

        # Convert to dict for storage
        metadata_dict = file_meta.to_dict()

        # Store in ChromaDB
        self.collection.upsert(
            ids=[doc_id],
            embeddings=_placeholder_embeddings(1),
            documents=[json.dumps(metadata_dict)],
            metadatas={
                "type": "file",
                "project_id": file_meta.project_id,
                "file_path": str(file_meta.file_path),
                "status": file_meta.status.value,
            },
        )

    def save_files_batch(self, file_metas: List[FileMetadata]) -> None:
        """Save or update multiple file metadata entries efficiently."""
        if not file_metas:
            return

        ids = []
        documents = []
        metadatas = []

        for file_meta in file_metas:
            doc_id = self._get_file_doc_id(file_meta.project_id, file_meta.file_path)
            metadata_dict = file_meta.to_dict()

            ids.append(doc_id)
            documents.append(json.dumps(metadata_dict))
            metadatas.append(
                {
                    "type": "file",
                    "project_id": file_meta.project_id,
                    "file_path": str(file_meta.file_path),
                    "status": file_meta.status.value,
                }
            )

        # Batch upsert
        self.collection.upsert(
            ids=ids,
            embeddings=_placeholder_embeddings(len(ids)),
            documents=documents,
            metadatas=metadatas,
        )

    def get_file(self, project_id: str, file_path: Path) -> Optional[FileMetadata]:
        """Get file metadata by project ID and file path."""
        doc_id = self._get_file_doc_id(project_id, file_path)

        try:
            results = self.collection.get(ids=[doc_id], include=["documents"])

            if results["documents"]:
                data = json.loads(results["documents"][0])
                return FileMetadata.from_dict(data)

            return None

        except Exception:
            return None

    def get_all_files(self, project_id: str) -> List[FileMetadata]:
        """Get all file metadata for a project."""
        try:
            results = self.collection.get(
                where={"$and": [{"type": "file"}, {"project_id": project_id}]},
                include=["documents"],
            )

            files = []
            for doc_json in results["documents"]:
                data = json.loads(doc_json)
                files.append(FileMetadata.from_dict(data))

            return files

        except Exception:
            return []

    def get_files_by_status(
        self, project_id: str, status: str
    ) -> List[FileMetadata]:
        """Get files by status (active, deleted, modified)."""
        try:
            results = self.collection.get(
                where={"$and": [{"type": "file"}, {"project_id": project_id}, {"status": status}]},
                include=["documents"],
            )

            files = []
            for doc_json in results["documents"]:
                data = json.loads(doc_json)
                files.append(FileMetadata.from_dict(data))

            return files

        except Exception:
            return []

    def delete_file(self, project_id: str, file_path: Path) -> bool:
        """Delete file metadata."""
        doc_id = self._get_file_doc_id(project_id, file_path)

        try:
            self.collection.delete(ids=[doc_id])
            return True
        except Exception:
            return False

    def delete_files_batch(self, project_id: str, file_paths: List[Path]) -> int:
        """Delete multiple file metadata entries efficiently."""
        ids = [self._get_file_doc_id(project_id, fp) for fp in file_paths]

        try:
            self.collection.delete(ids=ids)
            return len(ids)
        except Exception:
            return 0

    def mark_file_deleted(self, project_id: str, file_path: Path) -> bool:
        """Mark a file as deleted without removing metadata."""
        file_meta = self.get_file(project_id, file_path)

        if not file_meta:
            return False

        # Create updated metadata with deleted status
        updated_meta = FileMetadata(
            project_id=file_meta.project_id,
            file_path=file_meta.file_path,
            relative_path=file_meta.relative_path,
            language=file_meta.language,
            file_checksum=file_meta.file_checksum,
            file_size=file_meta.file_size,
            file_mtime=file_meta.file_mtime,
            git_commit_hash=file_meta.git_commit_hash,
            git_file_hash=file_meta.git_file_hash,
            indexed_at=file_meta.indexed_at,
            chunk_count=file_meta.chunk_count,
            embedding_ids=file_meta.embedding_ids,
            status=FileStatus.DELETED,
            last_scanned=datetime.now(),
        )

        self.save_file(updated_meta)
        return True

    # ===== Query Operations =====

    def get_file_paths(self, project_id: str) -> Set[Path]:
        """Get all file paths for a project."""
        try:
            results = self.collection.get(
                where={"$and": [{"type": "file"}, {"project_id": project_id}]},
                include=["metadatas"],
            )

            return {Path(meta["file_path"]) for meta in results["metadatas"]}

        except Exception:
            return set()

    def get_files_metadata_dict(self, project_id: str) -> Dict[Path, FileMetadata]:
        """Get all file metadata as a dictionary for efficient lookup."""
        files = self.get_all_files(project_id)
        return {f.file_path: f for f in files}

    def get_project_stats(self, project_id: str) -> Dict[str, int]:
        """Get statistics for a project."""
        all_files = self.get_all_files(project_id)

        active_files = sum(1 for f in all_files if f.status == FileStatus.ACTIVE)
        deleted_files = sum(1 for f in all_files if f.status == FileStatus.DELETED)
        total_chunks = sum(f.chunk_count for f in all_files)

        return {
            "total_files": len(all_files),
            "active_files": active_files,
            "deleted_files": deleted_files,
            "total_chunks": total_chunks,
        }

    # ===== Bulk Operations =====

    def clear_project_files(self, project_id: str) -> int:
        """Clear all file metadata for a project (keep project metadata)."""
        try:
            results = self.collection.get(
                where={"$and": [{"type": "file"}, {"project_id": project_id}]},
                include=["metadatas"],
            )

            if results["ids"]:
                self.collection.delete(ids=results["ids"])
                return len(results["ids"])

            return 0

        except Exception:
            return 0

    # ===== Helper Methods =====

    def _get_file_doc_id(self, project_id: str, file_path: Path) -> str:
        """
        Generate a unique document ID for a file.

        Uses hash of file path to create shorter, more manageable IDs.
        """
        import hashlib

        path_str = str(file_path)
        path_hash = hashlib.md5(path_str.encode()).hexdigest()[:12]
        return f"file_{project_id}_{path_hash}"
