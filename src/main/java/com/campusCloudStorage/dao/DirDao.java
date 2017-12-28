package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.Dir;

import java.util.List;


/**
 * 文件夹相关Dao
 */
public interface DirDao {
    /**
     * 删除指定主键的文件夹
     * @param dId 主键
     * @return 删除的数目，1为删除成功，0为删除失败
     */
    int deleteByPrimaryKey(Integer dId);

    /**
     * 插入一条完整记录record（不允许非空无默认值的字段为null）
     * @param record 记录
     * @return 插入的数目，1为插入成功，0为插入失败
     */
    int insert(Dir record);

    /**
     * 查询指定主键的文件夹记录
     * @param dId 主键
     * @return 指定主键的Dir对象
     */
    Dir selectByPrimaryKey(Integer dId);

    /**
     * 选择性更新记录，更新对象中的非空属性
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKeySelective(Dir record);

    /**
     * 查询拥有相同指定父目录的文件夹List
     * @param parentId 父目录
     * @return 文件夹List
     */
    List<Dir> selectByParentId(Integer parentId);
}