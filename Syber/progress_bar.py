from tqdm import tqdm

def progress_bar(total, desc="Progress", unit="task"):
    return tqdm(total=total, desc=desc, unit=unit)
