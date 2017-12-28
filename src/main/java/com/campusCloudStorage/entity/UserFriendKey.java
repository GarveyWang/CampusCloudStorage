package com.campusCloudStorage.entity;

/**
 * 用户好友联系主键类
 */
public class UserFriendKey {
    private Integer fromId;

    private Integer toId;

    public UserFriendKey() {
    }

    public UserFriendKey(Integer fromId, Integer toId) {
        this.fromId = fromId;
        this.toId = toId;
    }

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
}