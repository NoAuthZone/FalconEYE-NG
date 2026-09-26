"""Enhanced AST analyzer with control flow and data flow analysis."""

from pathlib import Path
from typing import List
import tree_sitter_language_pack

from ...domain.models.structural import (
    StructuralMetadata,
    FunctionInfo,
    ImportInfo,
    CallInfo,
    ClassInfo,
    ControlFlowNode,
)


class EnhancedASTAnalyzer:
    """
    Enhanced AST analyzer using Tree-sitter.

    Extracts structural metadata including:
    - Functions, imports, calls, classes
    - Control flow graphs (CFG)
    - Data flow information (DFG)

    IMPORTANT: This analyzer extracts metadata for AI context,
    NOT for pattern-based vulnerability detection.
    All security analysis is performed by the AI.
    """

    # Language mapping
    LANGUAGE_MAP = {
        '.py': 'python',
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.hpp': 'cpp',
        '.cc': 'cpp',
        '.rs': 'rust',
        '.go': 'go',
        '.php': 'php',
        '.java': 'java',
        '.dart': 'dart',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.ts': 'typescript',
        '.mts': 'typescript',
        '.cts': 'typescript',
        '.tsx': 'tsx',  # TSX needs its own tree-sitter grammar (JSX inside TypeScript)
    }

    def __init__(self):
        """Initialize AST analyzer."""
        self.parsers = {}
        self._init_parsers()

    def _init_parsers(self):
        """Initialize Tree-sitter parsers for supported languages."""
        for lang in set(self.LANGUAGE_MAP.values()):
            try:
                parser = tree_sitter_language_pack.get_parser(lang)
                self.parsers[lang] = parser
            except Exception as e:
                print(f"Warning: Could not initialize parser for {lang}: {e}")

    @staticmethod
    def _display_language(parser_language: str) -> str:
        """Map a tree-sitter grammar name to the FalconEYE language name."""
        return "typescript" if parser_language == "tsx" else parser_language

    def analyze_file(
        self,
        file_path: str,
        content: str,
    ) -> StructuralMetadata:
        """
        Analyze file and extract structural metadata.

        Args:
            file_path: Path to file
            content: File content

        Returns:
            StructuralMetadata with extracted information
        """
        # Determine language
        ext = Path(file_path).suffix.lower()
        language = self.LANGUAGE_MAP.get(ext)

        if not language or language not in self.parsers:
            # Return empty metadata for unsupported languages
            return StructuralMetadata(
                file_path=file_path,
                language=self._display_language(language) if language else "unknown"
            )

        # Parse code
        parser = self.parsers[language]
        tree = parser.parse(bytes(content, "utf8"))
        root = tree.root_node

        # Create metadata
        metadata = StructuralMetadata(
            file_path=file_path,
            language=self._display_language(language)
        )

        # Extract based on language
        if language == "python":
            self._analyze_python(root, content, metadata)
        elif language in ["c", "cpp"]:
            self._analyze_c_cpp(root, content, metadata)
        elif language == "rust":
            self._analyze_rust(root, content, metadata)
        elif language == "go":
            self._analyze_go(root, content, metadata)
        elif language in ["javascript", "typescript", "tsx"]:
            self._analyze_javascript(root, content, metadata)
        elif language == "java":
            self._analyze_java(root, content, metadata)
        elif language == "dart":
            self._analyze_dart(root, content, metadata)
        elif language == "php":
            self._analyze_php(root, content, metadata)

        return metadata

    def _analyze_python(self, root, content: str, metadata: StructuralMetadata):
        """Analyze Python code."""
        # Extract functions
        functions = self._find_nodes_by_type(root, "function_definition")
        for func_node in functions:
            name_node = func_node.child_by_field_name("name")
            if name_node:
                params = self._extract_python_params(func_node)
                is_async = func_node.child_by_field_name("async") is not None

                metadata.functions.append(FunctionInfo(
                    name=name_node.text.decode("utf8"),
                    line=func_node.start_point[0] + 1,
                    parameters=params,
                    is_async=is_async,
                ))

        # Extract imports
        imports = self._find_nodes_by_type(root, "import_statement")
        for imp_node in imports:
            statement = imp_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=imp_node.start_point[0] + 1,
                module=self._extract_module_name(statement),
            ))

        # Extract from imports
        from_imports = self._find_nodes_by_type(root, "import_from_statement")
        for imp_node in from_imports:
            statement = imp_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=imp_node.start_point[0] + 1,
                module=self._extract_module_name(statement),
                is_relative=statement.startswith("from ."),
            ))

        # Extract function calls
        calls = self._find_nodes_by_type(root, "call")
        for call_node in calls:
            func_node = call_node.child_by_field_name("function")
            if func_node:
                metadata.calls.append(CallInfo(
                    function=func_node.text.decode("utf8"),
                    line=call_node.start_point[0] + 1,
                ))

        # Extract classes
        classes = self._find_nodes_by_type(root, "class_definition")
        for class_node in classes:
            name_node = class_node.child_by_field_name("name")
            if name_node:
                metadata.classes.append(ClassInfo(
                    name=name_node.text.decode("utf8"),
                    line=class_node.start_point[0] + 1,
                ))

        # Extract control flow (simplified for now)
        self._extract_control_flow_python(root, metadata)

    def _analyze_c_cpp(self, root, content: str, metadata: StructuralMetadata):
        """Analyze C/C++ code."""
        # Extract functions
        functions = self._find_nodes_by_type(root, "function_definition")
        for func_node in functions:
            declarator = func_node.child_by_field_name("declarator")
            if declarator:
                name = self._get_function_name_c(declarator)
                if name:
                    metadata.functions.append(FunctionInfo(
                        name=name,
                        line=func_node.start_point[0] + 1,
                    ))

        # Extract includes
        includes = self._find_nodes_by_type(root, "preproc_include")
        for inc_node in includes:
            statement = inc_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=inc_node.start_point[0] + 1,
                module=self._extract_include_name(statement),
            ))

        # Extract calls
        calls = self._find_nodes_by_type(root, "call_expression")
        for call_node in calls:
            func_node = call_node.child_by_field_name("function")
            if func_node:
                metadata.calls.append(CallInfo(
                    function=func_node.text.decode("utf8"),
                    line=call_node.start_point[0] + 1,
                ))

    def _analyze_rust(self, root, content: str, metadata: StructuralMetadata):
        """Analyze Rust code."""
        # Extract functions
        functions = self._find_nodes_by_type(root, "function_item")
        for func_node in functions:
            name_node = func_node.child_by_field_name("name")
            if name_node:
                is_async = any(
                    child.type == "async" for child in func_node.children
                )
                metadata.functions.append(FunctionInfo(
                    name=name_node.text.decode("utf8"),
                    line=func_node.start_point[0] + 1,
                    is_async=is_async,
                ))

        # Extract use statements
        uses = self._find_nodes_by_type(root, "use_declaration")
        for use_node in uses:
            statement = use_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=use_node.start_point[0] + 1,
                module="",
            ))

    def _analyze_go(self, root, content: str, metadata: StructuralMetadata):
        """Analyze Go code."""
        # Extract functions
        functions = self._find_nodes_by_type(root, "function_declaration")
        for func_node in functions:
            name_node = func_node.child_by_field_name("name")
            if name_node:
                metadata.functions.append(FunctionInfo(
                    name=name_node.text.decode("utf8"),
                    line=func_node.start_point[0] + 1,
                ))

        # Extract imports
        imports = self._find_nodes_by_type(root, "import_declaration")
        for imp_node in imports:
            statement = imp_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=imp_node.start_point[0] + 1,
                module="",
            ))

    def _analyze_javascript(self, root, content: str, metadata: StructuralMetadata):
        """Analyze JavaScript/TypeScript code."""
        # Extract functions
        func_types = (
            "function_declaration",
            "generator_function_declaration",
            "arrow_function",
            "function",
            "function_expression",
            "method_definition",
        )
        # Single traversal for all function-like node types
        for func_node in self._find_nodes_by_type(root, func_types):
            # "function" is also the type of the keyword token -> only
            # count named (syntax) nodes, not the keyword itself
            if not func_node.is_named:
                continue
            name_node = func_node.child_by_field_name("name")
            if name_node is None and func_node.parent is not None:
                # const foo = () => {} / const foo = function () {}
                if func_node.parent.type in ("variable_declarator", "public_field_definition"):
                    name_node = func_node.parent.child_by_field_name("name")
            name = name_node.text.decode("utf8") if name_node else "anonymous"

            is_async = any(
                child.type == "async" for child in func_node.children
            )

            metadata.functions.append(FunctionInfo(
                name=name,
                line=func_node.start_point[0] + 1,
                is_async=is_async,
            ))

        # Extract imports (covers ESM imports and TS "import x = require()")
        imports = self._find_nodes_by_type(root, "import_statement")
        for imp_node in imports:
            statement = imp_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=imp_node.start_point[0] + 1,
                module="",
            ))

    def _analyze_java(self, root, content: str, metadata: StructuralMetadata):
        """Analyze Java code."""
        # Extract methods
        methods = self._find_nodes_by_type(root, "method_declaration")
        for method_node in methods:
            name_node = method_node.child_by_field_name("name")
            if name_node:
                metadata.functions.append(FunctionInfo(
                    name=name_node.text.decode("utf8"),
                    line=method_node.start_point[0] + 1,
                ))

        # Extract imports
        imports = self._find_nodes_by_type(root, "import_declaration")
        for imp_node in imports:
            statement = imp_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=imp_node.start_point[0] + 1,
                module="",
            ))

        # Extract classes
        classes = self._find_nodes_by_type(root, "class_declaration")
        for class_node in classes:
            name_node = class_node.child_by_field_name("name")
            if name_node:
                metadata.classes.append(ClassInfo(
                    name=name_node.text.decode("utf8"),
                    line=class_node.start_point[0] + 1,
                ))

    def _analyze_dart(self, root, content: str, metadata: StructuralMetadata):
        """Analyze Dart code."""
        # Extract functions
        functions = self._find_nodes_by_type(root, "function_signature")
        for func_node in functions:
            name_node = func_node.child_by_field_name("name")
            if name_node:
                metadata.functions.append(FunctionInfo(
                    name=name_node.text.decode("utf8"),
                    line=func_node.start_point[0] + 1,
                ))

        # Extract imports
        imports = self._find_nodes_by_type(root, "import_specification")
        for imp_node in imports:
            statement = imp_node.text.decode("utf8")
            metadata.imports.append(ImportInfo(
                statement=statement,
                line=imp_node.start_point[0] + 1,
                module="",
            ))

    def _analyze_php(self, root, content: str, metadata: StructuralMetadata):
        """Analyze PHP code."""
        # Extract functions
        functions = self._find_nodes_by_type(root, "function_definition")
        for func_node in functions:
            name_node = func_node.child_by_field_name("name")
            if name_node:
                metadata.functions.append(FunctionInfo(
                    name=name_node.text.decode("utf8"),
                    line=func_node.start_point[0] + 1,
                ))

    def _find_nodes_by_type(self, root, node_type) -> List:
        """
        Find all nodes of a type (or of any type in a collection of types).

        Iterative depth-first walk in source order: no recursion limit on
        deeply nested code (bundled/generated JS/TS) and faster than the
        previous recursive closure.
        """
        types = {node_type} if isinstance(node_type, str) else set(node_type)
        nodes = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in types:
                nodes.append(node)
            children = node.children
            if children:
                stack.extend(reversed(children))
        return nodes

    def _extract_python_params(self, func_node) -> List[str]:
        """Extract parameter names from Python function."""
        params = []
        params_node = func_node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "identifier":
                    params.append(child.text.decode("utf8"))
        return params

    def _extract_module_name(self, statement: str) -> str:
        """Extract module name from import statement."""
        parts = statement.split()
        if "import" in parts:
            idx = parts.index("import")
            if idx + 1 < len(parts):
                return parts[idx + 1].split(".")[0]
        return ""

    def _extract_include_name(self, statement: str) -> str:
        """Extract include name from C/C++ include."""
        import re
        match = re.search(r'[<"]([^>"]+)[>"]', statement)
        return match.group(1) if match else ""

    def _get_function_name_c(self, declarator):
        """Extract function name from C declarator."""
        if declarator.type == "identifier":
            return declarator.text.decode("utf8")

        for child in declarator.children:
            if child.type == "identifier":
                return child.text.decode("utf8")
            name = self._get_function_name_c(child)
            if name:
                return name

        return None

    def _extract_control_flow_python(self, root, metadata: StructuralMetadata):
        """
        Extract control flow nodes for Python.

        This provides context for AI analysis, NOT for pattern-based detection.
        """
        # Extract if statements
        if_statements = self._find_nodes_by_type(root, "if_statement")
        for if_node in if_statements:
            condition_node = if_node.child_by_field_name("condition")
            condition_text = condition_node.text.decode("utf8") if condition_node else None

            cf_node = ControlFlowNode(
                node_type="if",
                line=if_node.start_point[0] + 1,
                condition=condition_text,
            )
            metadata.control_flow.append(cf_node)

        # Extract while loops
        while_loops = self._find_nodes_by_type(root, "while_statement")
        for while_node in while_loops:
            condition_node = while_node.child_by_field_name("condition")
            condition_text = condition_node.text.decode("utf8") if condition_node else None

            cf_node = ControlFlowNode(
                node_type="while",
                line=while_node.start_point[0] + 1,
                condition=condition_text,
            )
            metadata.control_flow.append(cf_node)

        # Extract for loops
        for_loops = self._find_nodes_by_type(root, "for_statement")
        for for_node in for_loops:
            cf_node = ControlFlowNode(
                node_type="for",
                line=for_node.start_point[0] + 1,
            )
            metadata.control_flow.append(cf_node)

        # Extract try-except blocks
        try_statements = self._find_nodes_by_type(root, "try_statement")
        for try_node in try_statements:
            cf_node = ControlFlowNode(
                node_type="try",
                line=try_node.start_point[0] + 1,
            )
            metadata.control_flow.append(cf_node)