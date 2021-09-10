import os

# 这里是你文件的根目录
path = "C:/Users/12056/data"


# 遍历path路径下的所有文件（包括子文件夹下的文件）
def iterFilename(path):
    # 将os.walk在元素中提取的值，分别放到root（根目录），dirs（目录名），files（文件名）中。
    for root, dirs, files in os.walk(path):
        for file in files:
            # 根目录与文件名组合，形成绝对路径。
            yield os.path.join(root, file)


# 检查文件中是否包含关键词,若包含返回True, 若不包含返回False
def checkKeyword(save_path,filename, kwList):
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
        for kw in kwList:
            if kw in content:
                with open(save_path+"\\total.txt", "a", encoding="utf-8") as w:
                    w.write(content)
                #print(content)
                return True, kw
    return False, ""


if __name__ == "__main__":
    # 存储最终筛选结果的文件的目录
    save_path = "data"
    # 关键词数组
    kwList = ["经济", "贸易"]
    # 遍历文章
    for file in iterFilename(path):
        res, kw = checkKeyword(save_path,file, kwList)
        if res:
            # 如果包含关键词，打印文件名和匹配到的关键词
            print("文件 ", file, " 中包含关键词 ", kw)