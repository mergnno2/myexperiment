import pandas as pd
import seaborn as sns  #用于绘制热图的工具包
from scipy.cluster import hierarchy  #用于进行层次聚类，话层次聚类图的工具包
from scipy import cluster   
import matplotlib.pyplot as plt
from sklearn import decomposition as skldec #用于主成分分析降维的包
from sklearn.preprocessing import scale
import scipy.cluster.hierarchy as sch
import numpy as np



wbclust = pd.read_excel("flow_detect.xls",index_col=0)
print(wbclust.isnull().any())
data = np.array(wbclust.dropna())
wbnorm = scale(data[:,1:])
Z = hierarchy.linkage(wbnorm, method ='ward',metric='euclidean',optimal_ordering=False)
hierarchy.dendrogram(Z,labels=wbclust.index)
plt.show()


"""#1. 层次聚类
#生成点与点之间的距离矩阵,这里用的欧氏距离:
disMat = sch.distance.pdist(wbnorm,'euclidean') 
#进行层次聚类:
Z=sch.linkage(disMat,method='average') 
#将层级聚类结果以树状图表示出来并保存为plot_dendrogram.png
P=sch.dendrogram(Z)
plt.savefig('plot_dendrogram.png')
#根据linkage matrix Z得到聚类结果:
cluster= sch.fcluster(Z,t=2,criterion='maxclust') 

print ("Original cluster by hierarchy clustering:\n",cluster)
plt.show()"""
