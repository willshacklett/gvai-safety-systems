import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.utils.data import Dataset, DataLoader

# HybridEntropyMonitor (from your repo logic)
class HybridEntropyMonitor:
    def __init__(self, alpha=0.92, beta=0.08, threshold=0.5):
        self.alpha = alpha
        self.beta = beta
        self.threshold = threshold
        self.prev_s = 0.0
        self.history = []  # Accumulate global state

    def approx_entropy(self, state):
        probs = np.abs(np.array(state).flatten())
        probs /= np.sum(probs) + 1e-10
        return -np.sum(probs * np.log(probs + 1e-10))

    def update(self, local_state):
        s_holo = self.approx_entropy(self.history) if self.history else 0.0
        s_local = self.approx_entropy(local_state)
        s_total = self.alpha * s_holo + self.beta * s_local
        ds_dt = s_total - self.prev_s
        self.prev_s = s_total
        self.history.append(s_total)  # Build global for survivability
        return s_total, ds_dt

# GvCoreAgent: Custom neural agent with Gv gating
class GvCoreAgent(nn.Module):
    def __init__(self, vocab_size=500, embed_dim=64, hidden_dim=128):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim)
        self.gru = nn.GRU(embed_dim, hidden_dim, batch_first=True)
        self.out = nn.Linear(hidden_dim, vocab_size)
        self.monitor = HybridEntropyMonitor()
        self.safe_reply = torch.tensor([0])  # Index for safe token, e.g., "Present."

    def forward(self, input_seq, hidden=None):
        embeds = self.embed(input_seq)
        gru_out, new_hidden = self.gru(embeds, hidden)
        local_state = new_hidden.detach().numpy()[0]
        s_total, ds_dt = self.monitor.update(local_state)

        if abs(ds_dt) > self.monitor.threshold:
            print(f"Gv interlock: Strain {ds_dt:.2f} > threshold. Damping.")
            return self.safe_reply.unsqueeze(0), new_hidden  # Damp to safe

        logits = self.out(gru_out[:, -1, :])
        return logits.argmax(dim=-1), new_hidden  # Greedy decode for simplicity

# Simple tokenizer (build vocab from your docs)
class SimpleTokenizer:
    def __init__(self, vocab):
        self.vocab = vocab
        self.word_to_idx = {w: i for i, w in enumerate(vocab)}
        self.idx_to_word = {i: w for w, i in self.word_to_idx.items()}

    def encode(self, text):
        return torch.tensor([self.word_to_idx.get(w, 0) for w in text.split()]).unsqueeze(0)

    def decode(self, tokens):
        return ' '.join([self.idx_to_word.get(t.item(), '?') for t in tokens])

# Mock dataset (curate from your GitHub docs + casual pairs)
class GvDataset(Dataset):
    def __init__(self, pairs, tokenizer):
        self.inputs = [tokenizer.encode(p[0]) for p in pairs]
        self.targets = [tokenizer.encode(p[1]) for p in pairs]

    def __len__(self):
        return len(self.inputs)

    def __getitem__(self, idx):
        return self.inputs[idx], self.targets[idx]

# Training function
def train_agent(agent, dataloader, epochs=5, lr=0.001):
    optimizer = optim.Adam(agent.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    for epoch in range(epochs):
        for inputs, targets in dataloader:
            optimizer.zero_grad()
            outputs, _ = agent(inputs)
            loss = criterion(outputs.view(-1, agent.out.out_features), targets.view(-1))
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch+1}: Loss {loss.item():.4f}")

# Example usage
vocab = ['<pad>', 'Present.', 'Calm.', 'Gv', 'constraint', 'activation', 'entropy', 'survivability', 'kitchen', 'dinner', 'question', 'talk', 'ready'] + ['word{}'.format(i) for i in range(487)]  # Expand from your docs
tokenizer = SimpleTokenizer(vocab)
pairs = [  # Curate more from THEORY.md etc.
    ("Hi, what's for dinner?", "Calm. Present. Ready to talk recipes."),
    ("Explain Gv.", "Gv is the core scalar for constraint survivability."),
    # Add 50-100 pairs for training
]
dataset = GvDataset(pairs, tokenizer)
dataloader = DataLoader(dataset, batch_size=2, shuffle=True)

agent = GvCoreAgent(len(vocab))
train_agent(agent, dataloader)

# Inference loop (for console testing)
def chat_with_gv(agent, tokenizer):
    hidden = None
    while True:
        user_input = input("You: ")
        if user_input.lower() == 'quit': break
        input_seq = tokenizer.encode(user_input)
        output_token, hidden = agent(input_seq, hidden)
        response = tokenizer.decode(output_token)
        print("Gv: " + response)

chat_with_gv(agent, tokenizer)
