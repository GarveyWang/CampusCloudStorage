package com.campusCloudStorage.entity;

/**
 * 好友文件共享联系主键类
 */
public class UserFileShareKey {
    private Integer fromId;

    private Integer toId;

    private Integer fId;

    public Integer getFromId() {
        return fromId;
    }

    public void setFromId(Integer fromId) {
        this.fromId = fromId;
    }

    public Integer getToId() {
        return toId;
    }

    public void setToId(Integer toId) {
        this.toId = toId;
    }

    public Integer getfId() {
        return fId;
    }

    public void setfId(Integer fId) {
        this.fId = fId;
    }
}