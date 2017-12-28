package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.User;

/**
 * 用户相关的Dao
 */
public interface UserDao {

    /**
     * 插入指定用户记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(User record);

    /**
     * 选择性插入指定用户记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insertSelective(User record);

    /**
     * 查询指定主键的用户记录
     * @param uId 主键
     * @return 拥有指定主键的用户记录
     */
    User selectByPrimaryKey(Integer uId);

    /**
     * 选择性更新指定主键的用户记录，仅更新非空字段
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKeySelective(User record);

    /**
     * 更新指定主键的用户记录，更新所有字段
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKey(User record);

    //int deleteByPrimaryKey(Integer uId);
}