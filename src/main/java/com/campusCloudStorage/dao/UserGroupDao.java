package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.UserGroup;

import java.util.List;

/**
 * 群组相关的Dao
 */
public interface UserGroupDao {
    /**
     * 根据主键删除指定群组记录
     * @param gId 主键
     * @return 删除的数目，1为成功，0为失败
     */
    int deleteByPrimaryKey(Integer gId);

    /**
     * 插入群组记录，非空字段不允许为空值
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(UserGroup record);

    /**
     * 选择性插入群组记录，允许某些特定字段为空
     * @param record 记录
     * @return
     */
    int insertSelective(UserGroup record);

    /**
     * 根据主键查询特定群组
     * @param gId 主键
     * @return 该主键对应的群组对象
     */
    UserGroup selectByPrimaryKey(Integer gId);

    /**
     * 根据创建者Id查询其创建的群组
     * @param builderId 创建者Id
     * @return 该用户创建的群组List
     */
    List<UserGroup> selectByBuilderId(Integer builderId);

    /**
     * 根据记录中的非空属性，更新群组的相应字段
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKeySelective(UserGroup record);

    /**
     * 根据记录，更新群组的所有字段
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKey(UserGroup record);
}