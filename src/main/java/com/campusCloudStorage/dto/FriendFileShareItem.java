package com.campusCloudStorage.dto;

import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.entity.UserFileShare;

/**
 * 用于向好友分享文件界面传输数据的类
 * 包含好友分享信息，以及文件详情
 */
public class FriendFileShareItem {
    //好友分享文件信息，主要是因为要用到里面的remark属性
    private UserFileShare userFileShare;

    //文件信息
    private FileHeader fileHeader;

    public UserFileShare getUserFileShare() {
        return userFileShare;
    }

    public void setUserFileShare(UserFileShare userFileShare) {
        this.userFileShare = userFileShare;
    }

    public FileHeader getFileHeader() {
        return fileHeader;
    }

    public void setFileHeader(FileHeader fileHeader) {
        this.fileHeader = fileHeader;
    }
}
