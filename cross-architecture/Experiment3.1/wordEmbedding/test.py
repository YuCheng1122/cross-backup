from gensim.models import Word2Vec
import pickle
from tqdm import tqdm

# # 1. 載入訓練好的 model
# model_path = "/home/tommy/Projects/cross-architecture/Vector/20250509_train/model/word2vec_20250509_train.model"
# model = Word2Vec.load(model_path)

# # 2. 載入測試語料（list of list of tokens）
# test_pkl = "/home/tommy/Projects/cross-architecture/Vector/20250509_test/model/sentences_all_20250509_test.pkl"
# with open(test_pkl, "rb") as f:
#     test_sentences = pickle.load(f)

# # 3. 計算 coverage
# total_tokens = 0
# covered_tokens = 0

# # 使用 tqdm 包裝 sentence 層級
# for sent in tqdm(test_sentences, desc="Processing sentences"):
#     for token in sent:
#         total_tokens += 1
#         if token in model.wv:
#             covered_tokens += 1

# # 4. 計算 type-level
# unique_test_tokens = set(token for sent in test_sentences for token in sent)
# in_vocab_types = {token for token in unique_test_tokens if token in model.wv}

# # 5. 輸出結果
# print(f"Token-level coverage: {covered_tokens}/{total_tokens} = {covered_tokens/total_tokens*100:.2f}%")
# print(f"Type-level coverage: {len(in_vocab_types)}/{len(unique_test_tokens)} = {len(in_vocab_types)/len(unique_test_tokens)*100:.2f}%")

import pickle
from gensim.models import Word2Vec
import difflib
from tqdm import tqdm

# 1. 載入訓練好的 Word2Vec
model = Word2Vec.load(
    "/home/tommy/Projects/cross-architecture/Vector/20250509_train/model/word2vec_20250509_train.model"
)

# 2. 載入測試語料
with open(
    "/home/tommy/Projects/cross-architecture/Vector/20250509_test/model/sentences_all_20250509_test.pkl",
    "rb",
) as f:
    test_sentences = pickle.load(f)

# 3. 找出所有 unique token
unique_tokens = set(tok for sent in test_sentences for tok in sent)

# 4. 篩出 OOV token
oov_tokens = [tok for tok in unique_tokens if tok not in model.wv]
print(f"OOV 類型總數: {len(oov_tokens)}")

# 5. 針對前 20 個 OOV，用 difflib 找字串最相似的 5 個 in-vocab 候選詞
for tok in tqdm(oov_tokens[:20], desc="matching OOV"):
    candidates = difflib.get_close_matches(
        tok,                 # 要比對的字串
        model.wv.index_to_key,  # 語料庫所有詞
        n=5,                 # 取前 5 個最相似
        cutoff=0.6           # 相似度門檻（0~1）
    )
    print(f"{tok!r}  -> {candidates}")

