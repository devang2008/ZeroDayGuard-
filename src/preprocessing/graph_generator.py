"""
Graph Generator for Code Analysis
Generates AST, CFG, and PDG from source code
"""

import networkx as nx
import re
from typing import Dict, List, Tuple
import numpy as np


class SimpleGraphGenerator:
    """
    Simplified graph generator for C/C++ code
    Creates basic control flow and dependency graphs
    """
    
    def __init__(self):
        self.node_id = 0
        
    def reset(self):
        """Reset node ID counter"""
        self.node_id = 0
    
    def _get_next_id(self) -> int:
        """Get next node ID"""
        node_id = self.node_id
        self.node_id += 1
        return node_id
    
    def generate_ast(self, source_code: str) -> nx.DiGraph:
        """
        Generate simplified AST from source code
        
        Args:
            source_code: C/C++ source code string
            
        Returns:
            NetworkX directed graph representing AST
        """
        self.reset()
        G = nx.DiGraph()
        
        # Root node
        root_id = self._get_next_id()
        G.add_node(root_id, type='root', label='Program')
        
        # Extract functions
        func_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{([^}]*)\}'
        functions = re.finditer(func_pattern, source_code, re.DOTALL)
        
        for func_match in functions:
            func_id = self._get_next_id()
            func_name = func_match.group(2)
            func_body = func_match.group(3)
            
            G.add_node(func_id, type='function', label=func_name)
            G.add_edge(root_id, func_id, edge_type='contains')
            
            # Add statements as children
            statements = [s.strip() for s in func_body.split(';') if s.strip()]
            for stmt in statements:
                stmt_id = self._get_next_id()
                stmt_type = self._classify_statement(stmt)
                G.add_node(stmt_id, type=stmt_type, label=stmt[:50])
                G.add_edge(func_id, stmt_id, edge_type='statement')
        
        return G
    
    def generate_cfg(self, source_code: str) -> nx.DiGraph:
        """
        Generate simplified Control Flow Graph
        
        Args:
            source_code: C/C++ source code string
            
        Returns:
            NetworkX directed graph representing CFG
        """
        self.reset()
        G = nx.DiGraph()
        
        # Entry node
        entry_id = self._get_next_id()
        G.add_node(entry_id, type='entry', label='Entry')
        current_id = entry_id
        
        # Remove comments
        code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        
        # Split into statements
        statements = [s.strip() for s in re.split(r'[;{}]', code) if s.strip()]
        
        for stmt in statements:
            stmt_id = self._get_next_id()
            
            if re.match(r'\s*if\s*\(', stmt):
                # If statement
                G.add_node(stmt_id, type='condition', label='if')
                G.add_edge(current_id, stmt_id, edge_type='control')
                
                # True and false branches
                true_id = self._get_next_id()
                false_id = self._get_next_id()
                G.add_node(true_id, type='branch', label='true')
                G.add_node(false_id, type='branch', label='false')
                G.add_edge(stmt_id, true_id, edge_type='true')
                G.add_edge(stmt_id, false_id, edge_type='false')
                
                current_id = stmt_id
                
            elif re.match(r'\s*while\s*\(', stmt) or re.match(r'\s*for\s*\(', stmt):
                # Loop statement
                G.add_node(stmt_id, type='loop', label='loop')
                G.add_edge(current_id, stmt_id, edge_type='control')
                
                # Loop body and exit
                body_id = self._get_next_id()
                G.add_node(body_id, type='loop_body', label='body')
                G.add_edge(stmt_id, body_id, edge_type='body')
                G.add_edge(body_id, stmt_id, edge_type='back_edge')  # Loop back
                
                current_id = stmt_id
                
            else:
                # Regular statement
                stmt_type = self._classify_statement(stmt)
                G.add_node(stmt_id, type=stmt_type, label=stmt[:30])
                G.add_edge(current_id, stmt_id, edge_type='sequence')
                current_id = stmt_id
        
        # Exit node
        exit_id = self._get_next_id()
        G.add_node(exit_id, type='exit', label='Exit')
        G.add_edge(current_id, exit_id, edge_type='control')
        
        return G
    
    def generate_pdg(self, source_code: str) -> nx.DiGraph:
        """
        Generate simplified Program Dependence Graph
        
        Args:
            source_code: C/C++ source code string
            
        Returns:
            NetworkX directed graph representing PDG
        """
        self.reset()
        G = nx.DiGraph()
        
        # Track variable definitions and uses
        var_defs = {}  # variable -> node_id
        
        # Split into statements
        statements = [s.strip() for s in re.split(r'[;{}]', source_code) if s.strip()]
        
        for stmt in statements:
            stmt_id = self._get_next_id()
            stmt_type = self._classify_statement(stmt)
            G.add_node(stmt_id, type=stmt_type, label=stmt[:50])
            
            # Check for variable definitions (assignments)
            assign_match = re.match(r'(\w+)\s*=\s*(.+)', stmt)
            if assign_match:
                var_name = assign_match.group(1)
                rhs = assign_match.group(2)
                
                # Data dependency: this statement defines var_name
                var_defs[var_name] = stmt_id
                
                # Check what variables are used in RHS
                used_vars = re.findall(r'\b(\w+)\b', rhs)
                for used_var in used_vars:
                    if used_var in var_defs:
                        # Add data dependency edge
                        G.add_edge(var_defs[used_var], stmt_id, 
                                  edge_type='data_dependency')
            
            # Check for variable declarations
            decl_match = re.match(r'(int|char|float|double|void)\s+(\w+)', stmt)
            if decl_match:
                var_name = decl_match.group(2)
                var_defs[var_name] = stmt_id
        
        return G
    
    def _classify_statement(self, stmt: str) -> str:
        """Classify statement type"""
        stmt = stmt.strip()
        
        if re.match(r'\s*if\s*\(', stmt):
            return 'if_statement'
        elif re.match(r'\s*while\s*\(', stmt):
            return 'while_loop'
        elif re.match(r'\s*for\s*\(', stmt):
            return 'for_loop'
        elif re.match(r'\s*return\s+', stmt):
            return 'return'
        elif '=' in stmt:
            return 'assignment'
        elif re.match(r'\w+\s*\(', stmt):
            return 'function_call'
        else:
            return 'statement'
    
    def generate_all_graphs(self, source_code: str) -> Dict[str, nx.DiGraph]:
        """
        Generate all three graph types (AST, CFG, PDG)
        
        Args:
            source_code: C/C++ source code string
            
        Returns:
            Dictionary containing all three graphs
        """
        return {
            'ast': self.generate_ast(source_code),
            'cfg': self.generate_cfg(source_code),
            'pdg': self.generate_pdg(source_code)
        }
    
    def get_graph_features(self, G: nx.DiGraph) -> np.ndarray:
        """
        Extract features from a graph
        
        Args:
            G: NetworkX graph
            
        Returns:
            NumPy array of graph features
        """
        features = []
        
        # Basic graph metrics
        features.append(G.number_of_nodes())
        features.append(G.number_of_edges())
        features.append(nx.density(G) if G.number_of_nodes() > 0 else 0)
        
        # Degree statistics
        if G.number_of_nodes() > 0:
            degrees = [d for n, d in G.degree()]
            features.append(np.mean(degrees))
            features.append(np.max(degrees))
            features.append(np.min(degrees))
        else:
            features.extend([0, 0, 0])
        
        # Centrality measures (if graph is not empty)
        if G.number_of_nodes() > 1:
            try:
                betweenness = nx.betweenness_centrality(G)
                features.append(np.mean(list(betweenness.values())))
            except:
                features.append(0)
        else:
            features.append(0)
        
        # Graph diameter (approximation)
        if G.number_of_nodes() > 1:
            try:
                # Use longest shortest path as approximation
                lengths = []
                for source in G.nodes():
                    for target in G.nodes():
                        if source != target and nx.has_path(G, source, target):
                            lengths.append(nx.shortest_path_length(G, source, target))
                features.append(max(lengths) if lengths else 0)
            except:
                features.append(0)
        else:
            features.append(0)
        
        return np.array(features, dtype=np.float32)
