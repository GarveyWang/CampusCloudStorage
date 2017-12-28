package com.campusCloudStorage.service;

import com.campusCloudStorage.entity.GroupMember;
import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.GroupRequestStateEnum;

import java.util.List;

public interface GroupMemberService {
    /**
     * 根据群组Id，成员Id，同意申请入群请求
     * @param gId 群组Id
     * @param memberId 申请者Id
     * @return 同意群组成员请求状态
     */
    GroupRequestStateEnum permitMemberRequest(int gId, int memberId);

    /**
     * 根据群组Id，成员Id，删除指定群组成员
     * @param gId 群组Id
     * @param memberId 成员Id
     * @return 删除状态
     */
    DeleteStateEnum deleteMember(int gId, int memberId);

    /**
     * 根据群组Id和用户Id拒绝入群请求
     * @param gId 群组Id
     * @param uId 用户Id
     * @return 拒绝入群请求状态
     */
    GroupRequestStateEnum refuseGroupRequest(int gId, int uId);

    /**
     * 通过主键选择对应群组成员对象
     * @param gId 群组Id
     * @param uId 成员Id
     * @return 群组成员对象
     */
    GroupMember selectByPrimaryKey(int gId, int uId);

    /**
     * 通过群组Id选择未被处理的加群用户List
     * @param gId 群组Id
     * @return 未被处理的加群用户信息List
     */
    List<User> selectUnpermittedMembers(int gId);

    /**
     * 发送入群请求
     * @param gId 群组Id
     * @param uId 请求者Id
     * @return 群组加入请求状态
     */
    GroupRequestStateEnum sendJoinRequests(int gId, int uId);
}
