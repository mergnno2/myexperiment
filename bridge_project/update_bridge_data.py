import re
from selenium.webdriver.common.keys import Keys
from selenium import webdriver
from time import sleep
import random
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By


# 烏托邦:
# http://82.156.191.66:8015/#/login
#
# 烏托邦:
# 账号：翁牛特旗公路管护和运输保障中心
#
# 烏托邦:
# 密码：cbms@2020
#
# 烏托邦:
# 桥梁日常巡查录入

# 首先cmd 打开 chrome.exe --remote-debugging-port=5777 --user-data-dir="D:\selenium_chrome"
chrome_options = Options()
chrome_options.add_experimental_option("debuggerAddress", "127.0.0.1:5777")
browser = webdriver.Chrome(chrome_options=chrome_options)
print(browser.current_url)

'''button_select_bridge_3 = browser.find_element(by=By.XPATH,
                                              value='//*[@id="mainContainer"]/main/div[2]/div[1]/div/div/table/tbody/tr/td[2]/div/div[1]/span[4]/span/span/span/span/button')

button_bridge_group = []
for i in range(1, 111):
    button_bridge_group.append(browser.find_element(by=By.XPATH,
                                                    value='/html/body/div[3]/div/div[2]/div/div[2]/div[2]/div/div[2]/div/div[3]/div[1]/span/ul/li/ul/li[' + str(
                                                        i) + ']/span[2]'))'''

date_file = open("date_information.txt", 'r', newline='')
dates = []
for line in date_file:
    dates.append(line[:-2])
# 这个是开始日期 11-02--305
start_date = 386
# 这个是结束日期 503 对应的是2022-5-19
end_date = 515
i = start_date
while i <= end_date:
    print(dates[i])
    # 这个是复制那个蓝色的字
    button_copy = browser.find_element(by=By.XPATH,
                                       value='/html/body/div[1]/div/section/section/main/div[2]/div[2]/div/div/div/div/div/div/div/div[2]/table/tbody/tr[1]/td[6]/div/span/span[2]/a')
    #button_copy.click()
    browser.execute_script("arguments[0].click();", button_copy)
    sleep(0.2)

    # 这个是日期那个长条框
    button_clear = browser.find_element(by=By.XPATH, value='/html/body/div[7]/div/div[2]/div/div[2]/div[2]/div[1]/div/div/form/div[1]/div[1]/div/div[2]/div/span/span/div/input')
    browser.execute_script("arguments[0].click();", button_clear)
    sleep(0.2)

    # 这个是日期那个长条框点击之后
    button_clear = browser.find_element(by=By.XPATH, value='/html/body/div[8]/div/div/div/div/div[1]/div/input')
    button_clear.send_keys(Keys.CONTROL + 'a')
    sleep(0.2)

    button_clear.send_keys(Keys.BACK_SPACE)
    sleep(0.2)

    # 这个跟上面一样
    input_date = button_clear
    input_date.send_keys(dates[i])
    sleep(0.2)

    # 这个是右下角的保存按钮
    button_confirm = browser.find_element(by=By.XPATH, value='/html/body/div[7]/div/div[2]/div/div[2]/div[2]/div[2]/span/span[2]/button')
    button_confirm.click()
    sleep(0.3)
    i = i + 1
