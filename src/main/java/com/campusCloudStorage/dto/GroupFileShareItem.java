package com.campusCloudStorage.dto;

import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.entity.GroupFileShare;
import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.entity.UserFileShare;

/**
 * 用于向群组分享文件界面传输数据的类
 * 包含群组分享文件信息，文件详情，以及分享者的信息
 */
public class GroupFileShareItem {
    //群组分享信息，主要是因为要用到里面的remark属性
    private GroupFileShare groupFileShare;

    //分享文件
    private FileHeader fileHeader;

    //分享者
    private User provider;

    public GroupFileShare getGroupFileShare() {
        return groupFileShare;
    }

    public void setGroupFileShare(GroupFileShare groupFileShare) {
        this.groupFileShare = groupFileShare;
    }

    public FileHeader getFileHeader() {
        return fileHeader;
    }

    public void setFileHeader(FileHeader fileHeader) {
        this.fileHeader = fileHeader;
    }

    public User getProvider() {
        return provider;
    }

    public void setProvider(User provider) {
        this.provider = provider;
    }
}
