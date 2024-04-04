# ffmpeg -re -f video4linux2 -i /dev/video0 -vcodec libx264 -vprofile baseline -acodec aac -strict -2 -f flv rtmp://localhost/show/stream
# VIDEO_SOURCE=big_buck_bunny_240p_30mb.mp4
# ffmpeg -re -i $VIDEO_SOURCE -vcodec libx264 -vprofile baseline -g 30 -acodec aac -strict -2 -f flv rtmp://localhost/stream
python3 hls-stream/server.py hls-stream/testdata/m1-all_Custom.m3u8