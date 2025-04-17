import pandas as pd
import random

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

def sample_urls(input_file, output_file, n_samples=1000):
    df = pd.read_csv(input_file)
    assert 'url' in df.columns and 'status' in df.columns, "CSV must contain 'url' and 'status' columns"

    # Normalize URLs
    df = normalize_urls(df)
    
    # Take random sample
    if len(df) > n_samples:
        result_df = df.sample(n=n_samples, random_state=42)
    else:
        result_df = df
    
    # Rename and remap 'status' → 'result'
    result_df = result_df.rename(columns={'status': 'result'})
    result_df['result'] = result_df['result'].map({1: 1, 0: -1})
    
    result_df.to_csv(output_file, index=False)

# Example usage
sample_urls('responsive_urls.csv', 'test_urls.csv', n_samples=1000)
