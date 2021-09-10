import torch
import torch.utils.data as Data
import torch.nn as nn
from torch.utils.data import Dataset
from dataset import BasicDataset
import matplotlib.pyplot as plt



class Denoise(nn.Module):
    def __init__(self):
        super(Denoise, self).__init__()
        self.encoder = nn.Sequential(
            nn.Conv2d(1, 64, kernel_size=(3,3), padding=(1, 1), stride=(1, 1)),
            nn.PReLU(num_parameters=1),
            nn.Conv2d(64, 64, kernel_size=(3,3), padding=(1,1), stride=(1, 1), bias=False),
            nn.BatchNorm2d(64, eps=0.0001, momentum=0.95, affine=True, track_running_stats=True),
            nn.PReLU(num_parameters=1),
            nn.Conv2d(64, 64, kernel_size=(3, 3), stride=(1, 1), padding=(1, 1), bias=False),
            nn.BatchNorm2d(64, eps=0.0001, momentum=0.95, affine=True, track_running_stats=True),
            nn.PReLU(num_parameters=1),
            nn.Conv2d(64, 64, kernel_size=(3, 3), stride=(1, 1), padding=(1, 1), bias=False),
            nn.BatchNorm2d(64, eps=0.0001, momentum=0.95, affine=True, track_running_stats=True),
            nn.PReLU(num_parameters=1),
            nn.Conv2d(64, 64, kernel_size=(3, 3), stride=(1, 1), padding=(1, 1), bias=False),
            nn.BatchNorm2d(64, eps=0.0001, momentum=0.95, affine=True, track_running_stats=True),
            nn.PReLU(num_parameters=1),
            nn.Conv2d(64, 64, kernel_size=(3, 3), stride=(1, 1), padding=(1, 1), bias=False),
            nn.BatchNorm2d(64, eps=0.0001, momentum=0.95, affine=True, track_running_stats=True),
            nn.PReLU(num_parameters=1),
            nn.Conv2d(64, 1, kernel_size=(3, 3), stride=(1, 1), padding=(1, 1), bias=False)
        )

    def forward(self, x):
        x = self.encoder(x)
        return x

if __name__ == "__main__":
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    epoch = 1000
    LR = 0.0001
    batch_size = 20

    datasets = BasicDataset("D:\Python\Python37\myexperiment\Artificial_Intelligence\data\Denoise_Data.mat")
    train_loader = Data.DataLoader(dataset=datasets, batch_size=batch_size, shuffle=True)


    net = Denoise()
    net = net.to(device)
    parameters = list(net.parameters())
    loss_func = nn.MSELoss()
    optimizer = torch.optim.Adam(parameters, lr=LR)

    train_loss_list = []
    for epoch in range(epoch):
        train_loss = 0.0
        for step, batch in enumerate(train_loader):
            x = batch['image']
            x = x.to(device)
            y = batch['label']
            y = y.to(device)
            output = net(x)
            loss = loss_func(output, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        train_loss_list.append(train_loss / len(train_loader))
        print('Epoch :', epoch, '|', 'train_loss:%.8f' % (train_loss / len(train_loader)))

    plt.plot(range(epoch + 1), train_loss_list, "r", label="train_loss")
    plt.legend()
    plt.show()

    torch.save(net, "./model.pkl")


