"""ChromaDB-based metadata repository implementation."""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path
import chromadb
from chromadb.config import Settings

from ...domain.repositories.metadata_repository import MetadataRepository
from ...domain.models.structural import StructuralMetadata


# These collections are used as a key/value store only (lookups by id or
# metadata filter, never semantic queries). Passing explicit placeholder
# embeddings stops ChromaDB from running its default ONNX embedding model on
# every upsert, which otherwise downloads ~80 MB on first use (fails offline)
# and slows indexing. 384 = dimension of Chroma's default model, so existing
# collections stay compatible.
_PLACEHOLDER_DIM = 384


def _placeholder_embeddings(count: int) -> list:
    return [[0.0] * _PLACEHOLDER_DIM for _ in range(count)]


class ChromaMetadataRepository(MetadataRepository):
    """
    ChromaDB-based implementation for structural metadata storage.

    Stores AST-extracted metadata to provide rich context for AI analysis.
    This metadata is used for context assembly, NOT for pattern-based detection.
    """

    def __init__(
        self,
        persist_directory: str = "./chromadb",
        collection_name: str = "falconeye_metadata",
    ):
        """
        Initialize metadata repository.

        Args:
            persist_directory: Directory for ChromaDB persistence
            collection_name: Collection name for metadata
        """
        self.persist_directory = Path(persist_directory)
        self.collection_name = collection_name

        # Create directory if needed
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            )
        )

        # Get or create metadata collection
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "Structural metadata for AI context"}
        )

    async def store_metadata(
        self,
        metadata: StructuralMetadata,
    ) -> None:
        """
        Store structural metadata for a file.

        Args:
            metadata: Structural metadata to store
        """
        # Convert metadata to JSON
        metadata_json = json.dumps(metadata.to_dict())

        # Generate unique ID from file path
        doc_id = self._generate_id(metadata.file_path)

        # Store in ChromaDB
        self.collection.upsert(
            ids=[doc_id],
            embeddings=_placeholder_embeddings(1),
            documents=[metadata_json],
            metadatas=[{
                "file_path": metadata.file_path,
                "language": metadata.language,
                "functions_count": str(len(metadata.functions)),
                "imports_count": str(len(metadata.imports)),
                "calls_count": str(len(metadata.calls)),
                "classes_count": str(len(metadata.classes)),
            }]
        )

    async def get_metadata(
        self,
        file_path: str,
    ) -> Optional[StructuralMetadata]:
        """
        Retrieve metadata for a specific file.

        Args:
            file_path: Path to the file

        Returns:
            Structural metadata or None if not found
        """
        doc_id = self._generate_id(file_path)

        try:
            results = self.collection.get(
                ids=[doc_id],
                include=["documents", "metadatas"]
            )

            if results["ids"]:
                metadata_dict = json.loads(results["documents"][0])
                return self._dict_to_metadata(metadata_dict)

            return None

        except Exception:
            return None

    async def get_function_calls_graph(
        self,
        target_function: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get function call graph.

        Args:
            target_function: Optional filter for specific function

        Returns:
            Dictionary mapping files to their function calls
        """
        # Get all metadata
        results = self.collection.get(
            include=["documents"]
        )

        call_graph = {}
        for doc in results["documents"]:
            metadata_dict = json.loads(doc)
            file_path = metadata_dict["file_path"]

            calls = metadata_dict.get("calls", [])
            if target_function:
                # Filter for target function
                calls = [c for c in calls if target_function in c.get("function", "")]

            if calls:
                call_graph[file_path] = calls

        return call_graph

    async def get_dependency_graph(self) -> Dict[str, Dict[str, Any]]:
        """
        Get dependency graph showing imports and dependencies.

        Returns:
            Dictionary mapping files to their dependencies
        """
        results = self.collection.get(
            include=["documents"]
        )

        dependency_graph = {}
        for doc in results["documents"]:
            metadata_dict = json.loads(doc)
            file_path = metadata_dict["file_path"]

            dependency_graph[file_path] = {
                "dependencies": metadata_dict.get("dependencies", []),
                "imports": [imp.get("statement", "") for imp in metadata_dict.get("imports", [])],
                "import_count": len(metadata_dict.get("imports", [])),
            }

        return dependency_graph

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get aggregate statistics about the codebase.

        Returns:
            Dictionary with statistics
        """
        results = self.collection.get(
            include=["metadatas"]
        )

        total_files = len(results["ids"])
        total_functions = 0
        total_imports = 0
        total_calls = 0
        total_classes = 0
        language_breakdown = {}

        for metadata in results["metadatas"]:
            total_functions += int(metadata.get("functions_count", 0))
            total_imports += int(metadata.get("imports_count", 0))
            total_calls += int(metadata.get("calls_count", 0))
            total_classes += int(metadata.get("classes_count", 0))

            language = metadata.get("language", "unknown")
            language_breakdown[language] = language_breakdown.get(language, 0) + 1

        return {
            "total_files": total_files,
            "total_functions": total_functions,
            "total_imports": total_imports,
            "total_calls": total_calls,
            "total_classes": total_classes,
            "language_breakdown": language_breakdown,
        }

    async def search_functions(
        self,
        function_name: str,
    ) -> List[Dict[str, Any]]:
        """
        Search for functions by name.

        Args:
            function_name: Function name to search for

        Returns:
            List of matching functions with file locations
        """
        results = self.collection.get(
            include=["documents"]
        )

        matches = []
        for doc in results["documents"]:
            metadata_dict = json.loads(doc)
            file_path = metadata_dict["file_path"]

            for func in metadata_dict.get("functions", []):
                if function_name.lower() in func.get("name", "").lower():
                    matches.append({
                        "file_path": file_path,
                        "function_name": func["name"],
                        "line": func.get("line", 0),
                        "parameters": func.get("parameters", []),
                    })

        return matches

    def _generate_id(self, file_path: str) -> str:
        """
        Generate unique ID for file path.

        Args:
            file_path: File path

        Returns:
            Unique ID
        """
        # Use file path as ID (replace slashes for ChromaDB compatibility)
        return f"metadata_{file_path.replace('/', '_').replace('\\', '_')}"

    def _dict_to_metadata(self, data: Dict[str, Any]) -> StructuralMetadata:
        """
        Convert dictionary to StructuralMetadata object.

        Args:
            data: Dictionary representation

        Returns:
            StructuralMetadata object
        """
        from ...domain.models.structural import (
            FunctionInfo, ImportInfo, CallInfo, ClassInfo,
            DataFlowInfo
        )

        metadata = StructuralMetadata(
            file_path=data["file_path"],
            language=data["language"],
        )

        # Parse functions
        for func_data in data.get("functions", []):
            func = FunctionInfo(
                name=func_data["name"],
                line=func_data["line"],
                parameters=func_data.get("parameters", []),
                return_type=func_data.get("return_type"),
                is_async=func_data.get("is_async", False),
                decorators=func_data.get("decorators", []),
            )
            metadata.functions.append(func)

        # Parse imports
        for imp_data in data.get("imports", []):
            imp = ImportInfo(
                statement=imp_data["statement"],
                line=imp_data["line"],
                module=imp_data["module"],
                imported_names=imp_data.get("imported_names", []),
                is_relative=imp_data.get("is_relative", False),
            )
            metadata.imports.append(imp)

        # Parse calls
        for call_data in data.get("calls", []):
            call = CallInfo(
                function=call_data["function"],
                line=call_data["line"],
                call_type=call_data.get("call_type", "call"),
            )
            metadata.calls.append(call)

        # Parse classes
        for class_data in data.get("classes", []):
            cls = ClassInfo(
                name=class_data["name"],
                line=class_data["line"],
                bases=class_data.get("bases", []),
                methods=class_data.get("methods", []),
            )
            metadata.classes.append(cls)

        # Parse dependencies
        metadata.dependencies = data.get("dependencies", [])

        # Parse control flow (recursive)
        for cf_data in data.get("control_flow", []):
            cf_node = self._parse_control_flow_node(cf_data)
            metadata.control_flow.append(cf_node)

        # Parse data flows
        for df_data in data.get("data_flows", []):
            df = DataFlowInfo(
                variable=df_data["variable"],
                defined_at=df_data["defined_at"],
                used_at=df_data.get("used_at", []),
                is_tainted=df_data.get("is_tainted", False),
                flows_to=df_data.get("flows_to", []),
            )
            metadata.data_flows.append(df)

        return metadata

    def _parse_control_flow_node(self, data: Dict[str, Any]) -> Any:
        """Parse control flow node recursively."""
        from ...domain.models.structural import ControlFlowNode

        node = ControlFlowNode(
            node_type=data["node_type"],
            line=data["line"],
            condition=data.get("condition"),
        )

        for child_data in data.get("children", []):
            child = self._parse_control_flow_node(child_data)
            node.children.append(child)

        return node