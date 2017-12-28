package com.campusCloudStorage.service;

import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.entity.UserGroup;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.DeleteStateEnum;

import java.util.List;

/**
 * 群组相关服务
 */
public interface UserGroupService {
    /**
     * 根据群组Id得到对应群组对象
     * @param gId 群组Id
     * @return 对应群组对象
     */
    UserGroup selectByPrimaryKey(int gId);

    /**
     * 根据用户Id选择其创建的群组List
     * @param builderId 创建者Id
     * @return 创建的群组List
     */
    List<UserGroup> selectOwnedGroups(int builderId);

    /**
     * 根据用户Id选择其加入的非自建群组List
     * @param uId  用户Id
     * @return 加入的非自建群组List
     */
    List<UserGroup> selectJoinedGroups(int uId);

    /**
     * 根据用户Id选择其加入的以及创建的群组List
     * @param uId 用户Id
     * @return 加入的以及创建的群组List
     */
    List<UserGroup> selectOwnedAndJoinedGroups(int uId);

    /**
     * 根据群组Id选择群组成员对象List
     * @param gId 群组Id
     * @return 指定群组的成员对象List
     */
    List<User> selectMembers(int gId);

    /**
     * 根据群组Id选择群组创建者对象
     * @param gId 群组Id
     * @return 创建者对象
     */
    User selectOwner(int gId);

    /**
     * 删除群组以及群组内的成员，共享文件
     * @param uId 用户Id
     * @param gId 群组Id
     * @return 删除状态
     */
    DeleteStateEnum deleteUserGroup(int uId, int gId);

    /**
     * 创建群组
     * @param userGroup 群组
     * @return 创建状态
     */
    CreateStateEnum createUserGroup(UserGroup userGroup);
}
