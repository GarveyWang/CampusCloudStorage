package com.campusCloudStorage.enums;

/**
 * 登录状态枚举类
 */
public enum LoginStateEnum {
    SUCCESS(0,"登录成功！"),
    INFO_ERROR(1,"账号或密码错误！"),
    IMCOMPLETE(2,"账号信息不完整！");

    private int state;

    private String stateInfo;

    LoginStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static LoginStateEnum stateOf(int index){
        for(LoginStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
