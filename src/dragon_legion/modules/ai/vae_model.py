"""Variational Autoencoder for Unknown Protocol Discovery (Module 9).

PyTorch 1D-CNN VAE: encodes USB protocol byte sequences into latent space,
then uses Bayesian optimization to find latent points that maximize
device response entropy — discovering valid protocol handshakes
for unrecognized USB devices.

Architecture:
  Encoder: 3x Conv1D(filters=64,128,256) + GlobalAvgPool + Linear(→128) + Linear(→latent_dim*2)
  Decoder: Linear(128) → Linear(256) → Reshape → 3x ConvTranspose1D
"""

import numpy as np
import logging

logger = logging.getLogger(__name__)

# Try importing PyTorch — gracefully degrade if unavailable
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not available — VAE protocol discovery disabled")


if HAS_TORCH:

    class ProtocolVAE(nn.Module):
        """1D Convolutional Variational Autoencoder for USB protocol sequences.

        Input: (batch, 1, 128) — byte sequence padded/truncated to 128 bytes.
        Latent: 32-dimensional.

        Trained on known protocol sequences (DIAG, Sahara, Fastboot, AT commands, etc.).
        Bayesian optimization in latent space discovers novel protocol handshakes.
        """

        LATENT_DIM = 32
        INPUT_LEN = 128

        def __init__(self, latent_dim: int = 32):
            super().__init__()
            self.latent_dim = latent_dim

            # Encoder
            self.conv1 = nn.Conv1d(1, 64, kernel_size=5, stride=2, padding=2)
            self.conv2 = nn.Conv1d(64, 128, kernel_size=5, stride=2, padding=2)
            self.conv3 = nn.Conv1d(128, 256, kernel_size=3, stride=2, padding=1)
            self.bn1 = nn.BatchNorm1d(64)
            self.bn2 = nn.BatchNorm1d(128)
            self.bn3 = nn.BatchNorm1d(256)

            # After 3x stride-2: input 128 → 64 → 32 → 16
            # conv3 output: (batch, 256, 16)
            self.fc_mu = nn.Linear(256 * 16, latent_dim)
            self.fc_logvar = nn.Linear(256 * 16, latent_dim)

            # Decoder
            self.fc_decode = nn.Linear(latent_dim, 256 * 16)
            self.deconv1 = nn.ConvTranspose1d(256, 128, kernel_size=3, stride=2, padding=1, output_padding=1)
            self.deconv2 = nn.ConvTranspose1d(128, 64, kernel_size=5, stride=2, padding=2, output_padding=1)
            self.deconv3 = nn.ConvTranspose1d(64, 1, kernel_size=5, stride=2, padding=2, output_padding=1)
            self.bn_d1 = nn.BatchNorm1d(128)
            self.bn_d2 = nn.BatchNorm1d(64)

        def encode(self, x):
            """Encode byte sequence to latent parameters (mu, logvar)."""
            x = F.relu(self.bn1(self.conv1(x)))
            x = F.relu(self.bn2(self.conv2(x)))
            x = F.relu(self.bn3(self.conv3(x)))
            x = x.view(x.size(0), -1)  # Flatten
            mu = self.fc_mu(x)
            logvar = self.fc_logvar(x)
            return mu, logvar

        def reparameterize(self, mu, logvar):
            """Reparameterization trick: z = mu + sigma * eps."""
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std

        def decode(self, z):
            """Decode latent vector to reconstructed byte sequence."""
            x = self.fc_decode(z)
            x = x.view(x.size(0), 256, 16)
            x = F.relu(self.bn_d1(self.deconv1(x)))
            x = F.relu(self.bn_d2(self.deconv2(x)))
            x = torch.sigmoid(self.deconv3(x))  # Output in [0, 255]
            return x

        def forward(self, x):
            mu, logvar = self.encode(x)
            z = self.reparameterize(mu, logvar)
            recon = self.decode(z)
            return recon, mu, logvar

        def loss(self, x, recon, mu, logvar, beta: float = 1.0):
            """VAE loss = reconstruction loss (BCE) + beta * KL divergence.

            Beta-VAE (beta > 1) encourages disentangled latent representations.
            """
            batch_size = x.size(0)
            # Reconstruction: binary cross-entropy (bytes in [0, 255] normalized)
            recon_loss = F.mse_loss(recon, x, reduction="sum") / batch_size
            # KL divergence: -0.5 * sum(1 + logvar - mu^2 - exp(logvar))
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            kl_loss = kl_loss / batch_size
            return recon_loss + beta * kl_loss

        def discover_candidates(self, n_candidates: int = 100) -> torch.Tensor:
            """Sample from latent space to generate candidate protocol sequences.

            Uses trained decoder to generate novel byte sequences
            for Bayesian optimization evaluation.
            """
            with torch.no_grad():
                z = torch.randn(n_candidates, self.latent_dim)
                decoded = self.decode(z)
                # Scale to [0, 255] uint8 range
                decoded = (decoded * 255).clamp(0, 255).byte()
                return decoded

        def interpolate(self, z1: torch.Tensor, z2: torch.Tensor,
                        steps: int = 10) -> torch.Tensor:
            """Linear interpolation between two latent points → protocol variants."""
            alphas = torch.linspace(0, 1, steps).unsqueeze(1)
            z_interp = z1.unsqueeze(0) * (1 - alphas) + z2.unsqueeze(0) * alphas
            with torch.no_grad():
                decoded = self.decode(z_interp)
                return (decoded * 255).clamp(0, 255).byte()


    class ProtocolTrainer:
        """Train the ProtocolVAE on known USB protocol sequences."""

        def __init__(self, model: ProtocolVAE, lr: float = 1e-3):
            self.model = model
            self.optimizer = torch.optim.Adam(model.parameters(), lr=lr)
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)

        def bytes_to_tensor(self, sequences: list[bytes]) -> torch.Tensor:
            """Convert list of byte sequences to normalized tensor.

            Pads/truncates to ProtocolVAE.INPUT_LEN (128 bytes).
            """
            batch = np.zeros((len(sequences), 1, ProtocolVAE.INPUT_LEN), dtype=np.float32)
            for i, seq in enumerate(sequences):
                length = min(len(seq), ProtocolVAE.INPUT_LEN)
                batch[i, 0, :length] = np.frombuffer(seq[:length], dtype=np.uint8) / 255.0
            return torch.from_numpy(batch).to(self.device)

        def train_epoch(self, dataloader, beta: float = 1.0) -> float:
            """Train one epoch. Returns average loss."""
            self.model.train()
            total_loss = 0.0
            n_batches = 0

            for batch in dataloader:
                if isinstance(batch, (list, tuple)):
                    batch = batch[0]
                batch = batch.to(self.device)

                self.optimizer.zero_grad()
                recon, mu, logvar = self.model(batch)
                loss = self.model.loss(batch, recon, mu, logvar, beta=beta)
                loss.backward()
                self.optimizer.step()

                total_loss += loss.item()
                n_batches += 1

            return total_loss / max(n_batches, 1)

        def fit(self, sequences: list[bytes], epochs: int = 100,
                batch_size: int = 64, beta: float = 1.0) -> ProtocolVAE:
            """Train VAE on known protocol sequences.

            Known sequences include:
              - DIAG frames (start 0x7E + payload + CRC + end 0x7E)
              - Sahara packets (4B cmd + 4B len + 4B CRC32 + payload)
              - Fastboot commands (ASCII "getvar:xxx", "download:XXXX")
              - AT commands ("AT+xxx\r\n")
              - BROM packets (0xA0 + checksum + cmd + data)
              - Odin packets (ODIN magic + session + count)
            """
            tensor = self.bytes_to_tensor(sequences)
            dataset = torch.utils.data.TensorDataset(tensor)
            loader = torch.utils.data.DataLoader(
                dataset, batch_size=min(batch_size, len(sequences)),
                shuffle=True,
            )

            for epoch in range(epochs):
                avg_loss = self.train_epoch(loader, beta=beta)
                if epoch % 20 == 0:
                    logger.info("VAE epoch %d/%d: loss=%.4f", epoch, epochs, avg_loss)

            return self.model

        def save(self, path: str) -> None:
            torch.save({
                "model_state_dict": self.model.state_dict(),
                "latent_dim": self.model.latent_dim,
            }, path)
            logger.info("VAE model saved to %s", path)

        @classmethod
        def load(cls, path: str) -> "ProtocolVAE":
            checkpoint = torch.load(path, map_location="cpu")
            model = ProtocolVAE(latent_dim=checkpoint["latent_dim"])
            model.load_state_dict(checkpoint["model_state_dict"])
            return model


else:
    # Stub for when PyTorch is unavailable
    ProtocolVAE = None
    ProtocolTrainer = None
