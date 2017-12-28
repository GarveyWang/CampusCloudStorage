package com.campusCloudStorage.enums;

/**
 * 新建状态枚举类
 */
public enum CreateStateEnum {
    SUCCESS(0,"新建成功！"),
    DIR_NAME_REPEAT(1,"该文件夹已存在！"),
    IMCOMPLETE(2,"新建信息不完整！"),
    ILLEGAL_INFO(3,"新建信息不规范!"),
    FAILED(4,"新建失败");

    private int state;

    private String stateInfo;

    CreateStateEnum(int state, String stateInfo) {
        this.state = state;
        this.stateInfo = stateInfo;
    }

    public int getState() {
        return state;
    }

    public String getStateInfo() {
        return stateInfo;
    }

    public static CreateStateEnum stateOf(int index){
        for(CreateStateEnum stateEnum:values()){
            if(stateEnum.getState()==index){
                return stateEnum;
            }
        }
        return null;
    }
}
