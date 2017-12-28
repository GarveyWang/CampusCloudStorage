package com.campusCloudStorage.service;

import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.enums.LoginStateEnum;
import com.campusCloudStorage.enums.RegisterStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;

public interface UserService {
    /**
     * 根据用户Id获取该用户对象
     * @param uId 用户Id
     * @return 指定用户对象
     */
    User selectByPrimaryKey(int uId);

    /**
     * 用户注册
     * @param user 用户对象
     * @return 注册状态
     */
    RegisterStateEnum register(User user);

    /**
     * 用户验证
     * @param user 待验证的用户对象
     * @return 登录状态
     */
    LoginStateEnum validate(User user);

    /**
     * 用户更新
     * @param user 更新后的用户对象
     * @return 更新状态
     */
    UpdateStateEnum update(User user);

}
