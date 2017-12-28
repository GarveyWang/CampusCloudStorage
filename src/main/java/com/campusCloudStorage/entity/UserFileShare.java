package com.campusCloudStorage.entity;

/**
 * 好友文件共享联系类
 */
public class UserFileShare extends UserFileShareKey {
    private String remark;

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark == null ? null : remark.trim();
    }
}