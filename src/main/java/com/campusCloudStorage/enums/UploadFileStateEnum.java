package com.campusCloudStorage.enums;

/**
 * 文件上传状态枚举类
 */
public enum UploadFileStateEnum {
    SUCCESS(0,"上传成功！"),
    FAILED(1,"上传失败");

    private int state;

    private String stateInfo;

    UploadFileStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static UploadFileStateEnum stateOf(int index){
        for(UploadFileStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
