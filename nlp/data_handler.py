import codecs
import re
import jieba.posseg as pseg
from sklearn import feature_extraction
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.cluster import DBSCAN
import numpy as np


# DBSCAN聚类分析  虽然写在最前面，但这是最后调用的函数
def DBS_Visualization(epsnumber,min_samplesnumber,X_weight):
    DBS_clf = DBSCAN(eps=epsnumber,min_samples=min_samplesnumber)
    DBS_clf.fit(X_weight)
    labels_ = DBS_clf.labels_
    X_reduction = PCA(n_components=(max(labels_)+1)).fit_transform(X_weight)  #这个weight是不需要改变的
    X_reduction = TSNE(2).fit_transform(X_reduction)    #每次压缩的结果都是不一样的，因为n_components在变
    signal = 0
    noise = 0
    xyclfweight = [[[],[]] for k in range(max(labels_)+2)]
    for i in range(len(labels_)):
        if(labels_[i]==-1):
            noise += 1
            xyclfweight[-1][0].append(X_reduction[i][0])
            xyclfweight[-1][1].append(X_reduction[i][1])
        else:
            for j in range(max(labels_)+1):
                if(labels_[i]==j):
                    signal += 1
                    xyclfweight[j][0].append(X_reduction[i][0])
                    xyclfweight[j][1].append(X_reduction[i][1])
    colors = ['red','blue','green','yellow','black','magenta'] * 3
    for i in range(len(xyclfweight)-1):
        plt.plot(xyclfweight[i][0],xyclfweight[i][1],color=colors[i])
    plt.plot(xyclfweight[-1][0],xyclfweight[-1][1],color='#FFB6C1')
    # 自适应坐标轴
    plt.axis([min(X_reduction[:,0]),max(X_reduction[:,0]),min(X_reduction[:,1]),max(X_reduction[:,1])])
    plt.xlabel("x1")
    plt.ylabel("x2")
    plt.show()
    print("分类数量（含噪声-1，粉色）= "+str(max(labels_)+2),"  " + "信噪比 = "+str(signal/noise))  #包括噪声一共有多少类
    print("eps = "+str(epsnumber)+"  ", "min_sample = "+str(min_samplesnumber))


# 数据降噪处理
corpus = []
file = codecs.open("data\\total.txt","r","utf-8")
for line in file.readlines():
    corpus.append(line.strip())

stripcorpus = corpus.copy()
for i in range(len(corpus)):
    stripcorpus[i] = re.sub("@([\s\S]*?):","",corpus[i])  # 去除@ ...：
    stripcorpus[i] = re.sub("\[([\S\s]*?)\]","",stripcorpus[i])  # [...]：
    stripcorpus[i] = re.sub("@([\s\S]*?)","",stripcorpus[i])  # 去除@...
    stripcorpus[i] = re.sub("[\s+\.\!\/_,$%^*(+\"\']+|[+——！，。？、~@#￥%……&*（）]+","",stripcorpus[i])  # 去除标点及特殊符号
    stripcorpus[i] = re.sub("[^\u4e00-\u9fa5]","",stripcorpus[i])  #  去除所有非汉字内容（英文数字）
    stripcorpus[i] = re.sub("客户端","",stripcorpus[i])
    stripcorpus[i] = re.sub("回复","",stripcorpus[i])


# 接着，我们在只剩下汉语的stripcorpus列表中，将字符串长度小于5的去除，并使用jieba进行分词，代码如下所示
onlycorpus = []
for string in stripcorpus:
    if(string == ''):
        continue
    else:
        if(len(string)<5):
            continue
        else:
            onlycorpus.append(string)
cutcorpusiter = onlycorpus.copy()
cutcorpus = onlycorpus.copy()
cixingofword = []  # 储存分词后的词语对应的词性
wordtocixing = []  # 储存分词后的词语
for i in range(len(onlycorpus)):
    cutcorpusiter[i] = pseg.cut(onlycorpus[i])
    cutcorpus[i] = ""
    for every in cutcorpusiter[i]:
        cutcorpus[i] = (cutcorpus[i] + " " + str(every.word)).strip()
        cixingofword.append(every.flag)
        wordtocixing.append(every.word)
# 自己造一个{“词语”:“词性”}的字典，方便后续使用词性
word2flagdict = {wordtocixing[i]:cixingofword[i] for i in range(len(wordtocixing))}


#  短文本特征提取

vectorizer = CountVectorizer()
transformer = TfidfTransformer()#该类会统计每个词语的tf-idf权值
#第一个fit_transform是计算tf-idf 第二个fit_transform是将文本转为词频矩阵
tfidf = transformer.fit_transform(vectorizer.fit_transform(cutcorpus))
#获取词袋模型中的所有词语
word = vectorizer.get_feature_names()
#将tf-idf矩阵抽取出来，元素w[i][j]表示j词在i类文本中的tf-idf权重
weight = tfidf.toarray()


wordflagweight = [1 for i in range(len(word))]   #这个是词性系数，需要调整系数来看效果
for i in range(len(word)):
    if(word2flagdict[word[i]]=="n"):  # 这里只是举个例子，名词重要一点，我们就给它1.1
        wordflagweight[i] = 1.2
    elif(word2flagdict[word[i]]=="vn"):
        wordflagweight[i] = 1.1
    elif(word2flagdict[word[i]]=="m"):  # 只是举个例子，这种量词什么的直接去掉，省了一步停用词词典去除
        wordflagweight[i] = 0
    else:                                         # 权重数值还要根据实际情况确定，更多类型还请自己添加
        continue
wordflagweight = np.array(wordflagweight)
newweight = weight.copy()
for i in range(len(weight)):
    for j in range(len(word)):
        newweight[i][j] = weight[i][j]*wordflagweight[j]

# DBSCAN聚类分析
DBS_clf = DBSCAN(eps=1, min_samples=6)
DBS_clf.fit(newweight)
# 最后调用模型函数
DBS_Visualization(0.95, 6, newweight)

