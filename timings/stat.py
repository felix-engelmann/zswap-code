from glob import glob

def get_us(line):
    value = line.strip().split(" ")[-1]
    if value[-2:] != "μs":
        raise Exception("cannot parse")
    return int(value[:-2])

benched =  ["Homomorphic commitment took",
            "Spend proof took",
            "Output proof took",
            "Commitment checks took",
            "Spend proof verify took",
            "Output proof verify took",
            "Merging signature and tx took",
            "Consistency check took",
            "Randomness aggregation and transaction assembly took"]

def parse_test(file):
    data = {}
    with open(file) as fd:
        for line in fd:
            for parse in benched:
                if parse in line:
                    if parse not in data:
                        data[parse] = []
                    data[parse].append(get_us(line))
    return data


data = {}
for f in glob("data/run*"):
    d = parse_test(f)
    for k,v in d.items():
        if k not in data:
            data[k] = []
        data[k]+=v

med = {}
for k,v in data.items():
    median = sorted(v)[len(v)//2]
    med[k] = (median/1000, (median-min(v))/1000, (max(v)-median)/1000)
    print(k.ljust(55),f"{med[k][0]:8.3f} -{med[k][1]:8.3f} +{med[k][2]:8.3f} ms")

# pgfplots output
#for i,b in enumerate(benched):
#    print(f"({i}, {int(med[b][0]) if int(med[b][0])>10 else med[b][0]}) -= (0, {med[b][1]}) += (0, {med[b][2]})")
    
