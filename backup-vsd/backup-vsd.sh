#!/bin/bash

BACKUP_DIR='/mysql-backup/'
BACKUP_LOG_DIR=$BACKUP_DIR'log/'
DATE=`date +%Y%m%d-%H%M%S`
BACKUP_LOG=$BACKUP_LOG_DIR'vsd_backup-'$DATE'.log'
BACKUP_FILE=$BACKUP_DIR'vsd_backup-'$DATE'.tgz'

FTP_FOLDER=ftp://FtpServer/CONFIGS/LAB/VNS/
FTP_USER='anonymous'
FTP_PASSWORD=''

echo "" &> $BACKUP_LOG

#Run BACKUP
echo "*********************************************" &>> $BACKUP_LOG
echo "* VSD MySQL Backup                          *" &>> $BACKUP_LOG
echo "*********************************************" &>> $BACKUP_LOG
echo "" &>> $BACKUP_LOG
echo "innobackupex $BACKUP_DIR" &>> $BACKUP_LOG
innobackupex $BACKUP_DIR &>> $BACKUP_LOG

if [ -e $BACKUP_LOG ]
then
   #Apply MySQL sessions to backup
   CURRENT_BACKUP=`grep "Backup created" $BACKUP_LOG | awk -F"'" '{print $2}'`
   echo "Backup saved in $CURRENT_BACKUP" &>> $BACKUP_LOG
  
   echo "" &>> $BACKUP_LOG   
   echo "*********************************************" &>> $BACKUP_LOG
   echo "* Apply log to MySQL backup                 *" &>> $BACKUP_LOG
   echo "*********************************************" &>> $BACKUP_LOG
   echo "innobackupex --apply-log --use-memory=4G $CURRENT_BACKUP" &>> $BACKUP_LOG
   echo "" &>> $BACKUP_LOG

   innobackupex --apply-log --use-memory=4G $CURRENT_BACKUP &>> $BACKUP_LOG

   #Compress backup
   echo "" &>> $BACKUP_LOG
   echo "*********************************************" &>> $BACKUP_LOG
   echo "* Compressing VSD backup                    *" &>> $BACKUP_LOG
   echo "*********************************************" &>> $BACKUP_LOG
   echo "tar -zcf $BACKUP_FILE $CURRENT_BACKUP --remove-files" &>> $BACKUP_LOG 
   echo "" &>> $BACKUP_LOG  

   tar -zvcf $BACKUP_FILE $CURRENT_BACKUP --remove-files &>> $BACKUP_LOG

   #Generate MD5 from backup archive
   md5sum $BACKUP_FILE > $BACKUP_FILE'.md5'
fi


if [ -e $BACKUP_FILE ]
then
   #Transfer file to FTP
   echo "" &>> $BACKUP_LOG
   echo "*********************************************" &>> $BACKUP_LOG
   echo "* FTP backup to remote                      *" &>> $BACKUP_LOG
   echo "*********************************************" &>> $BACKUP_LOG
   echo "curl -T $BACKUP_FILE $FTP_FOLDER --user $FTP_USER:$FTP_PASSWORD" &>> $BACKUP_LOG
   echo "" &>> $BACKUP_LOG

   curl -T $BACKUP_FILE $FTP_FOLDER --user $FTP_USER:$FTP_PASSWORD &>> $BACKUP_LOG
   curl -T $BACKUP_FILE'.md5' $FTP_FOLDER --user $FTP_USER:$FTP_PASSWORD &>> $BACKUP_LOG
fi
