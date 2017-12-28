package com.campusCloudStorage.enums;

/**
 * 删除状态枚举类
 */
public enum DeleteStateEnum {
    SUCCESS(0,"删除成功"),
    FAILED(1,"删除失败");

    private int state;

    private String stateInfo;

    DeleteStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static DeleteStateEnum stateOf(int index){
        for(DeleteStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
