#! /bin/bash
start_time=$(date +%s)
firmware_path='../../../SaTC_dataset/firmware_SaTC'
process_firmware_bin(){  
    firmware_path=$1
	company=$2
	firm_dir=$3
	firm_bin=$4
	empty_str=""
	if [ $firm_bin == $empty_str ]
	then
		firm_bin=$firm_dir
		firm_dir=$empty_str
	fi
	fs_path="../../test_log/empty_dir"
	echo "in process_firmware_bin" $1 $2 $3 $4
	echo $firmware_path'/'$company'/'$firm_dir'/'$firm_bin
	tmp_dir_name=`openssl rand -hex 8` 
	mkdir $firmware_path'/'$company'/'$tmp_dir_name
	if [ ! -d  $firmware_path'/'$company'/'$firm_dir'/'$firm_bin ]
	then
		binwalk -Me $firmware_path'/'$company'/'$firm_dir'/'$firm_bin -C $firmware_path'/'$company'/'$tmp_dir_name
	else
		rm -r $firmware_path'/'$company'/'$firm_dir'/'$firm_bin
	fi
	for firm_bin in `ls $firmware_path'/'$company'/'$tmp_dir_name`
	do
		if [ -d  $firmware_path'/'$company'/'$tmp_dir_name'/'$firm_bin ]
		then
			echo `find $firmware_path'/'$company'/'$tmp_dir_name'/'$firm_bin -name "*-root"`
			fs_path=`find $firmware_path'/'$company'/'$tmp_dir_name'/'$firm_bin -name "*-root"`
		fi
	done
	echo $fs_path
	orig_fs="../../test_log/empty_dir"
	if [ $fs_path == $orig_fs ]
	then
		echo "can't find"
		echo $firm_dir" can't find fs_root" >> ../../test_log/time_log
		rm -r $firmware_path'/'$company'/'$tmp_dir_name
		return
	fi
	single_start_time=$(date +%s)
	i=1
	arr=""
	for fs_single_path in $fs_path
	do
		echo $fs_single_path
		#fs_single_name=($(echo $fs_single_path | tr "/" "\n"))
		#echo $fs_single_name
		arr=(${firm_dir//// })
		if [ $firm_dir == $empty_str ]
		then
			arr=$firm_bin
		fi
		echo ${arr[0]}
		python3 test_use_def.py -d $fs_single_path  -o '../../test_log/'${arr[0]} > '../../test_log/run_log/'${arr[0]}'-'$i'.log'
		i=$i+1
	done
	single_end_time=$(date +%s)
	cost_time=$[$single_end_time-$single_start_time]
	echo ${arr[0]}" cost time:"$cost_time" seconds" >> ../../test_log/time_log
	rm -r $firmware_path'/'$company'/'$tmp_dir_name
}  

tmp_fifofile="/tmp/$$.fifo"
mkfifo $tmp_fifofile # 新建一个fifo类型的文件
exec 6<>$tmp_fifofile # 将fd6指向fifo类型
rm $tmp_fifofile


thread=15 # 此处定义线程数
for ((i=0;i<$thread;i++));do
echo
done >&6 # 事实上就是在fd6中放置了$thread个回车符

for company in `ls $firmware_path` #三层目录结构，第一层目录代表厂商，第二层目录代表设备，每一个设备目录下有一个固件文件
do
	for device in `ls $firmware_path'/'$company`
	do
		orig_company=$company
		company=$company'/'$device
		if [ -d  $firmware_path'/'$company ]
		then
			thread_num=0
			for firm_bin in `ls $firmware_path'/'$company`
			do
			{
				echo $firm_bin
				firm_dir=""
				empty_str=""
				if [ ! -d  $firmware_path'/'$company'/'$firm_bin ] #对于每个固件，进行分析
				then
					if [[ $firm_bin = *.zip ]] #若为压缩包，解压
					then
						unziped_name=`unzip -v $firmware_path'/'$company'/'$firm_dir'/'$firm_bin | grep '/' | awk '{print $8}'`
						unziped_name=(${unziped_name%%/*})
						echo "unziped_name" $unziped_name
						if [ $unziped_name == $empty_str ]
						then
							echo "extract in the outer folder" #解压后没有生成子目录
							unzip $firmware_path'/'$company'/'$firm_dir'/'$firm_bin -d $firmware_path'/'$company'/'$firm_dir'unzip_folder'
							firm_dir="unzip_folder"
						else
							unzip $firmware_path'/'$company'/'$firm_dir'/'$firm_bin -d $firmware_path'/'$company'/'$firm_dir'/'
							firm_dir=$unziped_name
							
						fi
						echo $firmware_path'/'$company'/'$firm_dir #解压后的目录
						for firm_bin in `ls $firmware_path'/'$company'/'$firm_dir`
						do
							read -u6
							# 一个read -u6命令执行一次，就从fd6中减去一个回车符，然后向下执行，
							# fd6中没有回车符的时候，就停在这了，从而实现了线程数量控制

							{ # 此处子进程开始执行，被放到后台
							process_firmware_bin $firmware_path $company $firm_dir $firm_bin && { # 此处可以用来判断子进程的逻辑
							echo "one threadding is finished"
							} || {
							echo "threading error"
							}
							echo >&6 # 当进程结束以后，再向fd6中加上一个回车符，即补上了read -u6减去的那个
							} &
							
						done
						rm -r $firmware_path'/'$company'/'$firm_dir
					else #直接处理bin文件
						echo "firm_dir" $firm_dir "firmbin" $firm_bin
						read -u6
						# 一个read -u6命令执行一次，就从fd6中减去一个回车符，然后向下执行，
						# fd6中没有回车符的时候，就停在这了，从而实现了线程数量控制

						{ # 此处子进程开始执行，被放到后台
						process_firmware_bin $firmware_path $company $firm_dir $firm_bin && { # 此处可以用来判断子进程的逻辑
						echo "one threadding is finished"
						} || {
						echo "threading error"
						}
						echo >&6 # 当进程结束以后，再向fd6中加上一个回车符，即补上了read -u6减去的那个
						} &
							
					fi 
					
				fi
				
			} #&
			done
			
		fi
		company=$orig_company
	done
done
wait
exec 6>&- # 关闭df6
end_time=$(date +%s)
cost_time=$[$end_time-$start_time]
echo "total cost time:"$cost_time" seconds" >> ../../test_log/time_log