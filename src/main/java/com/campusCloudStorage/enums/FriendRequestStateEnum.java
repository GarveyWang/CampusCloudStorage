package com.campusCloudStorage.enums;

/**
 * 好友请求状态枚举类
 */
public enum FriendRequestStateEnum {
    SEND_SUCCESS(0,"好友请求发送成功！"),
    REPEAT(1,"请勿重复发送好友请求！"),
    SELF_REQUEST(2,"您查询的是自己的账号！"),
    NO_USER(3,"无此用户！"),
    PERMIT_SUCCESS(4,"同意好友请求成功"),
    PERMIT_FAIL(5,"同意好友请求失败"),
    DELETE_SUCCESS(6,"删除好友成功"),
    DELETE_FAIL(7,"删除好友失败");


    private int state;

    private String stateInfo;

    FriendRequestStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static FriendRequestStateEnum stateOf(int index){
        for(FriendRequestStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
