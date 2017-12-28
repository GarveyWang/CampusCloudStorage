package com.campusCloudStorage.entity;

import java.util.Date;
import java.util.List;

/**
 * 文件夹实体类
 */
public class Dir {
    private Integer dId;

    private String name;

    private Date createTime;

    private Integer parent;

    private List<Dir> childrenDirList;

    private List<FileHeader> childrenFileHeaderList;

    public Integer getdId() {
        return dId;
    }

    public void setdId(Integer dId) {
        this.dId = dId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name == null ? null : name.trim();
    }

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public Integer getParent() {
        return parent;
    }

    public void setParent(Integer parent) {
        this.parent = parent;
    }

    public List<Dir> getChildrenDirList() {
        return childrenDirList;
    }

    public void setChildrenDirList(List<Dir> childrenDirList) {
        this.childrenDirList = childrenDirList;
    }

    public List<FileHeader> getChildrenFileHeaderList() {
        return childrenFileHeaderList;
    }

    public void setChildrenFileHeaderList(List<FileHeader> childrenFileHeaderList) {
        this.childrenFileHeaderList = childrenFileHeaderList;
    }
}