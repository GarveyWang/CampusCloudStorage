package com.campusCloudStorage.enums;

/**
 * 更新状态枚举类
 */
public enum UpdateStateEnum {
    SUCCESS(0,"更新成功"),
    FAILED(1,"更新失败");

    private int state;

    private String stateInfo;

    UpdateStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static UpdateStateEnum stateOf(int index){
        for(UpdateStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
