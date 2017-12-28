package com.campusCloudStorage.dao;

import com.campusCloudStorage.entity.GroupMember;
import com.campusCloudStorage.entity.GroupMemberKey;


import java.util.List;

public interface GroupMemberDao {
    /**
     * 删除指定主键的群组成员
     * @param key 主键
     * @return 删除的数目，1为成功，0为失败
     */
    int deleteByPrimaryKey(GroupMemberKey key);

    /**
     * 删除指定群组Id的所有成员
     * @param gId 群组Id
     * @return 删除的成员数目
     */
    int deleteByGId(Integer gId);

    /**
     * 插入指定的群组成员记录
     * @param record 记录
     * @return 插入的数目，1为成功，0为失败
     */
    int insert(GroupMember record);

    /**
     * 查询指定主键的群组成员记录
     * @param key 主键
     * @return 拥有指定主键的群组成员记录
     */
    GroupMember selectByPrimaryKey(GroupMemberKey key);

    /**
     * 查询指定群组Id下的所有成员List
     * @param gId 群组Id
     * @return 指定群组Id的成员List
     */
    List<GroupMember> selectMembersByGId(Integer gId);

    /**
     * 查询指定用户的已被同意的群组成员记录List
     * @param uId 用户Id
     * @return 指定用户的已被同意的群组成员记录List
     */
    List<GroupMember> selectPermittedByUId(Integer uId);

    /**
     * 选择指定群组Id下未被同意的群组成员请求
     * @param gId 群组Id
     * @return 指定群组未被同意的群组成员记录List
     */
    List<GroupMember> selectUnpermittedMembers(Integer gId);

    /**
     * 更新指定主键的群组成员记录
     * @param record 记录
     * @return 更新的数目，1为成功，0为失败
     */
    int updateByPrimaryKey(GroupMember record);

    //int insertSelective(GroupMember record);

    //int updateByPrimaryKeySelective(GroupMember record);

}