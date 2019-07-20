from urllib.request import urlopen

with urlopen("http://uq.edu.au") as f:
    print(f.read(300))
