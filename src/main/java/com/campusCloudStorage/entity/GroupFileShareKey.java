package com.campusCloudStorage.entity;

/**
 * 群组文件共享联系的主键类
 */
public class GroupFileShareKey {
    private Integer gId;

    private Integer providerId;

    private Integer fId;

    public Integer getgId() {
        return gId;
    }

    public void setgId(Integer gId) {
        this.gId = gId;
    }

    public Integer getProviderId() {
        return providerId;
    }

    public void setProviderId(Integer providerId) {
        this.providerId = providerId;
    }

    public Integer getfId() {
        return fId;
    }

    public void setfId(Integer fId) {
        this.fId = fId;
    }
}