package com.campusCloudStorage.enums;

/**
 * 注册状态枚举类
 */
public enum RegisterStateEnum {
    SUCCESS(0,"注册成功！"),
    ID_REPEAT(1,"账号已存在！"),
    IMCOMPLETE(2,"账号信息不完整！"),
    ILLEGAL_INFO(3,"新建信息不规范"),
    FAILED(4,"注册失败");

    private int state;

    private String stateInfo;

    RegisterStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static RegisterStateEnum stateOf(int index){
        for(RegisterStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
