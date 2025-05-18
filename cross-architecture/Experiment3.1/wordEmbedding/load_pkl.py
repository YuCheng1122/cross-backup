from itertools import chain, islice
from pathlib import Path
from gensim.models import Word2Vec
from multiprocessing import Pool, cpu_count
from nltk import total_ordering
from tqdm import tqdm
import pandas as pd
from time import time
import os
from datetime import datetime
import logging
import joblib
from typing import List, Dict, Sequence, Tuple, Generator, Optional
from preprocessing import iterate_json_files, Pcode_to_sentence
import pickle

DATA_DIR = Path("/home/tommy/datasets/cross-architecture/results_merged")
TRAIN_CSV_PATH = Path("/home/tommy/Projects/cross-architecture/Experiment3.1/dataset/20250509_test.csv")
OUTPUT_DIR = Path("/home/tommy/Projects/cross-architecture/Vector/20250509_test/model")
PICKLE_PATH = OUTPUT_DIR / "sentences_20250509_test.pkl"
LOG_PATH = OUTPUT_DIR / "missing_files.log"
BATCH_FILES = 1000

if not OUTPUT_DIR.exists():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('missing_files')

def _file_to_sentences(file_name_data):
    file_name, data = file_name_data
    out = []
    try:
        out.extend(Pcode_to_sentence(data))
        # print(f"File: {file_name} - Sentences: {len(out)}")
    except Exception as e:
        print(f"Error processing file {file_name}: {e}")
    return out                                                                          

def corpus_generator(csv_path: Path, root_dir: Path, batch_files:int):
    file_iter = iterate_json_files(csv_path, root_dir)
    batch_num = 0
    while True:   
        current_batch = list(islice(file_iter, batch_files))
        if not current_batch:
            break 
        sentences = []
        with Pool(cpu_count()) as pool:
            for sent_list in tqdm(
                pool.imap_unordered(_file_to_sentences, current_batch, chunksize=1),
                total=len(current_batch),
                desc=f"Batch {batch_num}"
            ):
                sentences.extend(sent_list)
        out_path = OUTPUT_DIR / f"sentences_batch_{batch_num}.pkl"
        with open(out_path, "wb") as f:
            pickle.dump(sentences, f)
        logger.info(f"Saved batch {batch_num}: files={len(current_batch)}, sentences={len(sentences)}")

        del sentences
        del current_batch

        batch_num += 1

if __name__ == "__main__":
    corpus_generator(TRAIN_CSV_PATH, DATA_DIR, BATCH_FILES)
    
# print("Building vocabulary...")
# model = Word2Vec(
#         vector_size=256, 
#         sg=1, 
#         window=4,
#         min_count=3, 
#         workers=48,
#         seed=42,
# )
# model.build_vocab(sentences, progress_per=10000)

# print("Training Word2Vec model...")
# for epoch in range(2):
#     print(f"Epoch {epoch+1}/2")
#     model.train(
#         corpus_iterable=corpus_generator(TRAIN_CSV_PATH, DATA_DIR),
#         total_examples=model.corpus_count,
#         epochs=1,
#     )
# model.train(
# corpus_iterable=corpus_generator(TRAIN_CSV_PATH, DATA_DIR),
# total_examples=model.corpus_count,
# epochs=1,
# )

# model.save(str(OUTPUT_DIR / "word2vec_train_0509.model"))
# print("Vocabulary size: ",len(model.wv))
            
