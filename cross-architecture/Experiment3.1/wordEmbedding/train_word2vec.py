import pickle
from pathlib import Path
from gensim.models import Word2Vec
from tqdm import tqdm

print("Loading sentences from pickle…")
with open("/home/tommy/Projects/cross-architecture/Experiment3.1/output/sentences_all.pkl", "rb") as f:
    raw_sentences = pickle.load(f)

sentences = list(tqdm(raw_sentences, desc="Preparing sentences"))

model = Word2Vec(
    vector_size=256,
    sg=1,
    window=4,
    min_count=3,
    workers=48,
    seed=42,
)

model.build_vocab(
    tqdm(sentences, desc="Building vocab"),
    progress_per=10000
)

print("Training Word2Vec model…")
for epoch in range(2):
    print(f"Epoch {epoch+1}/2")
    model.train(
        corpus_iterable=tqdm(sentences, desc=f"Training epoch {epoch+1}"),
        total_examples=model.corpus_count,
        epochs=1,
    )
print("Saving model…")
model.save("word2vec_20250509_train.model")

# Check lens
print("Model lens: ",len(model.wv.key_to_index))

