"""
Production-Ready Model with Advanced Features
Includes: Attention, Multi-head processing, Ensemble capabilities
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class MultiHeadAttention(nn.Module):
    """Multi-head attention for feature importance"""
    
    def __init__(self, embed_dim, num_heads=4):
        super().__init__()
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads
        
        assert embed_dim % num_heads == 0, "embed_dim must be divisible by num_heads"
        
        self.query = nn.Linear(embed_dim, embed_dim)
        self.key = nn.Linear(embed_dim, embed_dim)
        self.value = nn.Linear(embed_dim, embed_dim)
        self.out = nn.Linear(embed_dim, embed_dim)
        
    def forward(self, x):
        batch_size = x.size(0)
        
        # Linear projections
        Q = self.query(x).view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        K = self.key(x).view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        V = self.value(x).view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        
        # Attention scores
        scores = torch.matmul(Q, K.transpose(-2, -1)) / (self.head_dim ** 0.5)
        attn_weights = F.softmax(scores, dim=-1)
        
        # Apply attention
        context = torch.matmul(attn_weights, V)
        context = context.transpose(1, 2).contiguous().view(batch_size, -1, self.num_heads * self.head_dim)
        
        return self.out(context), attn_weights


class ProductionVulnerabilityDetector(nn.Module):
    """
    Production-grade vulnerability detector with:
    - Multi-head attention for feature importance
    - Residual connections
    - Layer normalization
    - Ensemble-ready architecture
    """
    
    def __init__(
        self,
        code_feature_dim=24,
        graph_feature_dim=8,
        hidden_dim=512,
        num_classes=2,
        dropout=0.5,
        num_heads=4
    ):
        super().__init__()
        
        # Feature encoders
        input_dim = code_feature_dim + 3 * graph_feature_dim
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Multi-head attention
        self.attention = MultiHeadAttention(hidden_dim, num_heads)
        self.attn_norm = nn.LayerNorm(hidden_dim)
        
        # Deep processing layers with residual connections
        self.deep_layers = nn.ModuleList([
            self._make_residual_block(hidden_dim, dropout)
            for _ in range(3)
        ])
        
        # Vulnerability-specific features
        self.vuln_encoder = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.LayerNorm(hidden_dim // 4),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Classifier
        self.classifier = nn.Linear(hidden_dim // 4, num_classes)
        
        # For attention visualization
        self.last_attention_weights = None
        
    def _make_residual_block(self, dim, dropout):
        """Create residual block"""
        return nn.ModuleDict({
            'layers': nn.Sequential(
                nn.Linear(dim, dim),
                nn.LayerNorm(dim),
                nn.ReLU(),
                nn.Dropout(dropout)
            )
        })
    
    def forward(self, code_features, ast_features, cfg_features, pdg_features):
        # Combine all features
        x = torch.cat([code_features, ast_features, cfg_features, pdg_features], dim=1)
        
        # Initial encoding
        x = self.encoder(x)
        
        # Apply attention
        x_unsqueeze = x.unsqueeze(1)  # Add sequence dimension
        attn_out, attn_weights = self.attention(x_unsqueeze)
        self.last_attention_weights = attn_weights
        x = self.attn_norm(x + attn_out.squeeze(1))
        
        # Deep processing with residual connections
        for block in self.deep_layers:
            residual = x
            x = block['layers'](x)
            x = x + residual  # Residual connection
        
        # Vulnerability-specific encoding
        x = self.vuln_encoder(x)
        
        # Classification
        logits = self.classifier(x)
        
        return logits
    
    def get_attention_weights(self):
        """Get last attention weights for visualization"""
        return self.last_attention_weights


class EnsembleVulnerabilityDetector(nn.Module):
    """
    Ensemble of models for robust predictions
    Combines predictions from multiple models
    """
    
    def __init__(self, models):
        super().__init__()
        self.models = nn.ModuleList(models)
        
    def forward(self, code_features, ast_features, cfg_features, pdg_features):
        # Get predictions from all models
        predictions = []
        for model in self.models:
            logits = model(code_features, ast_features, cfg_features, pdg_features)
            probs = F.softmax(logits, dim=1)
            predictions.append(probs)
        
        # Average predictions (ensemble)
        ensemble_probs = torch.stack(predictions).mean(dim=0)
        
        # Convert back to logits
        ensemble_logits = torch.log(ensemble_probs + 1e-8)
        
        return ensemble_logits


def create_production_model(
    model_type='production',
    code_feature_dim=24,
    graph_feature_dim=8,
    hidden_dim=512,
    num_classes=2,
    dropout=0.5,
    num_ensemble=1
):
    """
    Create production-ready model
    
    Args:
        model_type: 'production' or 'ensemble'
        num_ensemble: Number of models in ensemble (if model_type='ensemble')
    """
    
    if model_type == 'production':
        return ProductionVulnerabilityDetector(
            code_feature_dim=code_feature_dim,
            graph_feature_dim=graph_feature_dim,
            hidden_dim=hidden_dim,
            num_classes=num_classes,
            dropout=dropout
        )
    
    elif model_type == 'ensemble':
        models = [
            ProductionVulnerabilityDetector(
                code_feature_dim=code_feature_dim,
                graph_feature_dim=graph_feature_dim,
                hidden_dim=hidden_dim,
                num_classes=num_classes,
                dropout=dropout
            )
            for _ in range(num_ensemble)
        ]
        return EnsembleVulnerabilityDetector(models)
    
    else:
        raise ValueError(f"Unknown model_type: {model_type}")


if __name__ == '__main__':
    # Test model
    model = create_production_model(
        model_type='production',
        hidden_dim=512
    )
    
    # Dummy input
    batch_size = 32
    code_feat = torch.randn(batch_size, 24)
    ast_feat = torch.randn(batch_size, 8)
    cfg_feat = torch.randn(batch_size, 8)
    pdg_feat = torch.randn(batch_size, 8)
    
    # Forward pass
    output = model(code_feat, ast_feat, cfg_feat, pdg_feat)
    
    print(f"Input shape: {code_feat.shape}")
    print(f"Output shape: {output.shape}")
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")
    print("\n✅ Production model working!")
