import numpy as np
from torch.utils.data import Dataset
import scipy.io as scio
import torch
import random

def gasuss_noise(image, mean=0, var=0.01):
    '''
        添加高斯噪声
        mean : 均值
        var : 方差
    '''

    image = np.array(image, dtype=float)
    noise = np.random.normal(mean, var ** 0.5, image.shape)
    out = image + noise
    if out.min() < 0:
        low_clip = -1.
    else:
        low_clip = 0.
    out = np.clip(out, low_clip, 1.0)

    #图像乘以255
    # out = np.uint8(out * 255)
    # cv.imshow("gasuss", out)
    return out


class BasicDataset(Dataset):
    def __init__(self, imgdir):
        self.imgdir = imgdir
        num = 100
        self.ids = [i for i in range(0, num)]

    def __len__(self):
        return len(self.ids)

    def preprocess(self, pil_img):
        # img_trans = gasuss_noise(pil_img)
        img_trans = pil_img.reshape((1, pil_img.shape[0], pil_img.shape[1]))        # print(img_trans.shape)


        return img_trans

    def __getitem__(self, i):
        img = scio.loadmat("./data/Denoise_Data.mat")
        img_origin = self.preprocess(img['S0'])

        c_list = ['S_n10', 'S_n20', 'S_n30']
        img_str = random.sample(c_list, 1)[0]
        # print(img_str)
        img_trans = self.preprocess(img[img_str])


        return {'image': torch.from_numpy(img_trans).type(torch.FloatTensor),
                'label': torch.from_numpy(img_origin).type(torch.FloatTensor)
        }


if __name__ == "__main__":
    x = BasicDataset("./data/Denoise_Data.mat")
    for item in x:
        print(item['image'])
