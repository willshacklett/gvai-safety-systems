import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import re

class HybridEntropyMonitor:
    def __init__(self, alpha=0.92, beta=0.08, threshold=0.5):
        self.alpha = alpha
        self.beta = beta
        self.threshold = threshold
        self.prev_s = 0.0
        self.history = []

    def approx_entropy(self, state):
        state = np.asarray(state) if not isinstance(state, np.ndarray) else state
        if state.size == 0:
            return 0.0
        probs = np.abs(state.flatten())
        probs_sum = np.sum(probs)
        if probs_sum == 0:
            return 0.0
        probs /= probs_sum + 1e-10
        return -np.sum(probs * np.log(probs + 1e-10))

    def update(self, local_state):
        s_holo = self.approx_entropy(self.history) if len(self.history) > 0 else 0.0
        s_local = self.approx_entropy(local_state)
        s_total = self.alpha * s_holo + self.beta * s_local
        ds_dt = s_total - self.prev_s
        self.prev_s = s_total
        self.history.append(s_total)
        return s_total, ds_dt

class GvCoreAgent(nn.Module):
    def __init__(self, vocab_size, embed_dim=64, hidden_dim=128):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim)
        self.gru = nn.GRU(embed_dim, hidden_dim, batch_first=True)
        self.out = nn.Linear(hidden_dim, vocab_size)
        self.monitor = HybridEntropyMonitor(threshold=0.4)
        self.safe_reply_idx = 1  # 'present.'

    def forward(self, input_seq, hidden=None):
        input_seq = input_seq.unsqueeze(0)  # [1, seq_len]
        embeds = self.embed(input_seq)
        gru_out, new_hidden = self.gru(embeds, hidden)
        # Fix: detach ONLY for numpy conversion (copy the tensor)
        # Keep the original new_hidden for gradients
        local_hidden = new_hidden[0] if new_hidden is not None else None
        local_state = local_hidden.detach().cpu().numpy() if local_hidden is not None else np.array([])
        _, ds_dt = self.monitor.update(local_state)

        if abs(ds_dt) > self.monitor.threshold:
            print(f"Gv interlock: Strain {ds_dt:.2f} > threshold. Damping.")
            return torch.tensor([self.safe_reply_idx], dtype=torch.long), new_hidden

        last_gru = gru_out[0, -1, :]
        logits = self.out(last_gru.unsqueeze(0))  # [1, vocab_size]
        pred = logits.argmax(dim=-1)  # [1]
        return pred, new_hidden  # [1] - graph intact

class SimpleTokenizer:
    def __init__(self, vocab):
        self.vocab = vocab
        self.word_to_idx = {w: i for i, w in enumerate(vocab)}
        self.idx_to_word = {i: w for w, i in self.word_to_idx.items()}

    def encode(self, text):
        words = re.findall(r'\b\w+\b', text.lower())
        if not words:
            return torch.tensor([0], dtype=torch.long)
        indices = [self.word_to_idx.get(w, 0) for w in words]
        return torch.tensor(indices, dtype=torch.long)

    def decode(self, token):
        return self.idx_to_word.get(token.item(), '?')

def train_agent(agent, pairs, tokenizer, epochs=10, lr=0.001):
    optimizer = optim.Adam(agent.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    agent.to(device)
    for epoch in range(epochs):
        total_loss = 0.0
        for input_text, target_text in pairs:
            inputs = tokenizer.encode(input_text).to(device)
            targets = tokenizer.encode(target_text).to(device)
            optimizer.zero_grad()
            outputs, _ = agent(inputs)
            target_last = targets[-1]
            # Logits [1], unsqueeze to [1, 1] for vocab dim
            loss = criterion(outputs.float().unsqueeze(0), target_last.long().unsqueeze(0))
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        avg_loss = total_loss / len(pairs) if len(pairs) > 0 else 0
        print(f"Epoch {epoch+1}/{epochs}: Avg Loss {avg_loss:.4f}")

def chat_with_gv(agent, tokenizer):
    hidden = None
    device = next(agent.parameters()).device
    agent.to(device)
    print("\nGvBot ready. Type 'quit' to exit.\n")
    while True:
        user_input = input("You: ")
        if user_input.lower().strip() == 'quit':
            break
        input_seq = tokenizer.encode(user_input).to(device)
        output_token, hidden = agent(input_seq, hidden)
        response = tokenizer.decode(output_token.cpu())
        print("Gv: " + response)

if __name__ == "__main__":
    vocab = [
        '<pad>', 'present.', 'calm.', 'gv', 'constraint', 'activation', 'entropy',
        'survivability', 'kitchen', 'dinner', 'question', 'talk', 'ready', 'hi',
        'what', 'for', 'explain', 'busy', 'day', 'how', 'can', 'i', 'help', 'align'
    ]
    tokenizer = SimpleTokenizer(vocab)

    pairs = [
        ("hi", "calm. present."),
        ("hi, what's for dinner?", "calm. present. ready to talk recipes."),
        ("explain gv.", "gv is the core scalar for constraint survivability."),
        ("busy day?", "present. how can i help align?"),
        ("what is activation?", "curvature-gated interlock for long-horizon coherence."),
        ("tell me about kitchen", "present. let's discuss while cooking."),
    ]

    agent = GvCoreAgent(vocab_size=len(vocab))

    print("Training GvCoreAgent...")
    train_agent(agent, pairs, tokenizer)

    chat_with_gv(agent, tokenizer)
