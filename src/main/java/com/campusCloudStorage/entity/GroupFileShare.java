package com.campusCloudStorage.entity;

/**
 * 群组文件分享联系类
 */
public class GroupFileShare extends GroupFileShareKey {
    private String remark;

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark == null ? null : remark.trim();
    }
}