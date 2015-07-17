本自動化script包含幾個部分：

1. get_events.sh
用來自動化登入Manager下載event，儲存成為 events.json

2. extract_ip.py / extract_dns.py
用來自動截取剛剛下載的 events.json ，取出目的IP/FQDN後儲存成為block_ip.txt或者block_dns.txt
本程式會參考相同目錄的 whitelist.txt ，該檔案必須存在，否則本程式會無法正常執行。

3. 使用一個shell script把以上兩隻程式放在一起執行，隨便取名，如 lastline.sh
該script內容很單純，依序執行 get_events.sh 跟 extract_ip.py 。可以視需求寫log。

4. 將第三點的script，加入到/etc/crontab內，設定排程執行。排程間隔最好別小於兩分鐘。
**注意** centos 6內，crontab必須定義執行程式所處的工作目錄：
0 * * * * root cd /root && /root/lastline.sh

如果是Ubuntu則不用：
*/10 * * * * root sh /home/tyler/lastline.sh