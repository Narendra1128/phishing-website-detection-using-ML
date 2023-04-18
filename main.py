from features_computing import feature_extraction
dict_1 = {}
with open("phishing.csv") as file:
    lines = [x.split("\n") for x in file]
    lines = [x[0] for x in lines]
    for i in lines:
        if i not in dict_1:
            dict_1[i] = None
final_list = []
for i in dict_1.keys():
    final_list.append(i)
with open("phishing_data.csv", "w") as file:
    for i in final_list:
        file.write(i+"\n")
