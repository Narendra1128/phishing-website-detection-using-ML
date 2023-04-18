from features_computing import feature_extraction

with open("phish.txt") as f:
    line = [x.split("\n")[0] for x in f]

with open("phi.csv", mode="a") as dd:
    for i in range(len(line)):
        x = feature_extraction(line[i], 1)
        x = [str(x) for x in x]
        x = ','.join(x)
        dd.write(x +"\n")
        print(i)