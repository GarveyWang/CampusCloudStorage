package com.campusCloudStorage.enums;

/**
 * 分享状态枚举类
 */
public enum ShareStateEnum {
    SUCCESS(0,"分享成功！"),
    REPEAT(1,"该文件已经分享过啦！"),
    FAIL(2,"分享失败！");


    private int state;

    private String stateInfo;

    ShareStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static ShareStateEnum stateOf(int index){
        for(ShareStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
