import pandas as pd
import random
import difflib

def is_similar(url1, url2, threshold=0.9):
    return difflib.SequenceMatcher(None, url1, url2).ratio() > threshold

def filter_dissimilar(urls, max_samples, similarity_threshold=0.9):
    selected = []
    for url in urls:
        if all(not is_similar(url, existing, similarity_threshold) for existing in selected):
            selected.append(url)
        if len(selected) == max_samples:
            break
    return selected

def normalize_urls(df):
    def fix_url(row):
        url = row['url']
        status = row['status']
        if not isinstance(url, str) or not url.strip():
            return url
        if not url.startswith(('http://', 'https://')):
            if status == 1:
                return 'https://' + url
            elif status == 0:
                return random.choice(['http://', 'https://']) + url
        return url

    df['url'] = df.apply(fix_url, axis=1)
    return df

def sample_balanced_subset(input_file, output_file, n_samples=1000, similarity_threshold=0.9):
    df = pd.read_csv(input_file)
    assert 'url' in df.columns and 'status' in df.columns, "CSV must contain 'url' and 'status' columns"

    df = normalize_urls(df)

    subset_rows = []

    for status_val in [0, 1]:
        group = df[df['status'] == status_val]
        urls = group['url'].tolist()
        random.shuffle(urls)

        filtered_urls = filter_dissimilar(urls, n_samples, similarity_threshold)
        filtered_df = group[group['url'].isin(filtered_urls)]

        if len(filtered_df) < n_samples:
            raise ValueError(f"Not enough dissimilar samples for status={status_val}")

        subset_rows.append(filtered_df)

    result_df = pd.concat(subset_rows).sample(frac=1).reset_index(drop=True)

    # Rename and remap 'status' → 'result'
    result_df = result_df.rename(columns={'status': 'result'})
    result_df['result'] = result_df['result'].map({1: 1, 0: -1})

    result_df.to_csv(output_file, index=False)

# Example usage
sample_balanced_subset('new_data_urls.csv', 'test_urls.csv', n_samples=1000, similarity_threshold=0.9)
