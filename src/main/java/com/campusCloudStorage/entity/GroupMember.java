package com.campusCloudStorage.entity;

/**
 * 群组成员联系类
 */
public class GroupMember extends GroupMemberKey {
    private Byte permitted;

    public Byte getPermitted() {
        return permitted;
    }

    public void setPermitted(Byte permitted) {
        this.permitted = permitted;
    }
}