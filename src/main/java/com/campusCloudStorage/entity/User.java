package com.campusCloudStorage.entity;

/**
 * 用户实体类
 */
public class User {
    private Integer uId;

    private String password;

    private String name;

    //该用户的根目录Id
    private Integer rootDir;

    //该用户的回收站目录Id
    private Integer recyclebin;

    private String type;

    public Integer getuId() {
        return uId;
    }

    public void setuId(Integer uId) {
        this.uId = uId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password == null ? null : password.trim();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name == null ? null : name.trim();
    }

    public Integer getRootDir() {
        return rootDir;
    }

    public void setRootDir(Integer rootDir) {
        this.rootDir = rootDir;
    }

    public Integer getRecyclebin() {
        return recyclebin;
    }

    public void setRecyclebin(Integer recyclebin) {
        this.recyclebin = recyclebin;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type == null ? null : type.trim();
    }
}