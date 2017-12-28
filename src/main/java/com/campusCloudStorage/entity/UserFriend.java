package com.campusCloudStorage.entity;

/**
 * 用户好友联系类
 */
public class UserFriend extends UserFriendKey {

    public UserFriend() {
    }

    public UserFriend(Integer fromId, Integer toId, Byte permitted) {
        super(fromId, toId);
        this.permitted = permitted;
    }

    private Byte permitted;

    public Byte getPermitted() {
        return permitted;
    }

    public void setPermitted(Byte permitted) {
        this.permitted = permitted;
    }
}